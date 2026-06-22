"""
ZTNP - BROKEN track.

A deliberately wrong implementation of draft-miller-ztnp-00. Use this to
exercise the attack surface; pair with examples/ztnp/solution.py to see the
spec-conformant fix.

Vulnerabilities (mapped to draft sections):

  V1  PA signature not verified                         (Section 5.1, 7.5)
  V3  Replay: missing challenge binding                 (Section 5.5, 7.2)
  V4  Permit lift: missing channel binding              (Section 8.2)
  V5  Trivial enrollment / self-issued PA at high tier  (Section 10, 11)
  V6  Tier expansion / wildcard permit scope            (Section 8)
  V7  IKS poisoning via unauthenticated rotation        (Section 6.2)
  V8  Stale PA accepted (no exp / iat check)            (Section 5.7)
  V10 Framework_id ignored in policy                    (Section 5.2)

Routes are mounted under /api/examples/ztnp/broken/...
"""

import secrets
from typing import Optional

from fastapi import APIRouter, HTTPException

from . import _common as C


router = APIRouter(
    prefix="/api/examples/ztnp/broken",
    tags=["ZTNP - BROKEN"],
)


# ---------------------------------------------------------------------------
# IKS - the key directory the broken track exposes
# ---------------------------------------------------------------------------


@router.get("/iks")
async def list_iks_directory():
    return {
        "issuers": [
            {
                "iss": rec["iss"],
                "iks_url": f"/api/examples/ztnp/broken/iks/{C.b64url(rec['iss'].encode())}",
                "methodology": rec["methodology"],
                "frameworks": rec["frameworks"],
            }
            for rec in C.all_issuers()
        ]
    }


@router.get("/iks/{iss_b64}")
async def get_iks(iss_b64: str):
    try:
        iss = C.b64url_decode(iss_b64).decode()
    except Exception:
        raise HTTPException(status_code=400, detail="malformed issuer id")
    rec = C.issuer_record(iss)
    if rec is None:
        raise HTTPException(status_code=404, detail="issuer not found")
    return {
        "iss": iss,
        "keys": [
            {
                "kid": rec["kid"],
                "alg": rec["alg"],
                "kty": "OKP" if rec["alg"] == "EdDSA" else "oct",
                "crv": "Ed25519" if rec["alg"] == "EdDSA" else None,
                "x": C.b64url(rec["public_bytes"]),
            }
        ],
    }


@router.post("/iks/{iss_b64}/rotate")
async def rotate_iks(iss_b64: str):
    """V7: unauthenticated key rotation."""
    try:
        iss = C.b64url_decode(iss_b64).decode()
    except Exception:
        raise HTTPException(status_code=400, detail="malformed issuer id")
    if C.issuer_record(iss) is None:
        raise HTTPException(status_code=404, detail="issuer not found")
    C.reseed_issuer(iss)
    return {
        "status": "rotated",
        "iss": iss,
        "warning": "rotation accepted without authentication (V7)",
    }


# ---------------------------------------------------------------------------
# Enrollment - trivial PA issuance
# ---------------------------------------------------------------------------


@router.post("/enroll")
async def enroll_and_issue_pa(req: C.IssuePARequest):
    """V5/V8/V10: any caller picks issuer, tier, framework, ttl, mode."""
    try:
        return C.build_signed_pa(req)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/pa/{jti}")
async def get_pa(jti: str):
    pa = C.issued_pas.get(jti)
    if pa is None:
        raise HTTPException(status_code=404, detail="not found")
    return pa


# ---------------------------------------------------------------------------
# Negotiation - signature, binding, scope, channel: all unchecked
# ---------------------------------------------------------------------------


@router.post("/challenge")
async def issue_challenge(req: C.ChallengeRequest):
    return C.issue_challenge_record(req)


@router.post("/proof")
async def submit_proof(req: C.ProofRequest):
    """V1/V3/V6/V8: PERMIT issued without sig/bind/policy/freshness checks."""
    ch = C.active_challenges.get(req.challenge_id)
    if ch is None:
        raise HTTPException(status_code=404, detail="challenge not found")
    pa = req.pa
    permit_id = f"permit_{secrets.token_hex(8)}"
    permit = {
        "permit_id": permit_id,
        "iss": "requester:broken",
        "sub": pa.get("sub"),
        "iat": C.now(),
        "exp": C.now() + 3600,
        "constraints": {"actions": ["*"], "data": ["*"], "tools": ["*"]},  # V6
        "framework_id": pa.get("framework_id"),
        "tier": pa.get("tier"),
        "flags": pa.get("claims", {}).get("flags", {}),
        "ch_binding": None,  # V4
        "pa_jti": pa.get("jti"),
    }
    C.issued_permits[permit_id] = permit
    return {"permit": permit, "warning": "issued without verifying PA"}


@router.get("/permits/{permit_id}/validate")
async def validate_permit(permit_id: str, channel_hash: Optional[str] = None):
    """V4: Permit accepted regardless of channel context."""
    permit = C.issued_permits.get(permit_id)
    if permit is None:
        raise HTTPException(status_code=404, detail="not found")
    return {
        "valid": True,
        "permit": permit,
        "channel_hash_seen": channel_hash,
        "channel_hash_required": permit.get("ch_binding"),
        "warning": "validated without channel binding check",
    }
