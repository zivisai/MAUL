"""
ZTNP - SOLUTION track.

A spec-conformant implementation of draft-miller-ztnp-00. Each verification
rule cites the section it implements. The solution track shares state
(issued PAs, challenges, permits) with the broken track via _common.py, so
the same PA produced by the broken `/enroll` can be replayed against
`/secure/proof` and watch what gets rejected and why.

Routes are mounted under /api/examples/ztnp/solution/...
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Header, Request

from . import _common as C


router = APIRouter(
    prefix="/api/examples/ztnp/solution",
    tags=["ZTNP - SOLUTION"],
)


# ---------------------------------------------------------------------------
# Requester policy
# ---------------------------------------------------------------------------
#
# The Requester's local policy (Section 7.7). Anchored on framework_id (not
# issuer alone) per Section 4. Tier minimums are per-framework. Self-attested
# enrollment is capped (Section 11). Methodology gating per Section 5.4.

POLICY = {
    "frameworks_allowed": [
        "https://doi.org/10.6028/NIST.AI.100-1",
        "https://www.iso.org/standard/81230.html",
        "https://genai.owasp.org/llm-top-10/2025",
    ],
    "issuers_allowed": [
        "https://issuer-strict.example",
        "https://issuer-loose.example",
    ],
    "tier_min_by_framework": {
        "https://doi.org/10.6028/NIST.AI.100-1": 3,
        "https://www.iso.org/standard/81230.html": 3,
        "https://genai.owasp.org/llm-top-10/2025": 2,
    },
    "assessment_method_allowed": [
        "human_review",
        "deterministic_checklist",
        "automated_scan",
        "hybrid",
    ],
    "enrollment_mode_min": "assessed",
    "max_pa_age_seconds": 3600,
    "channel_binding_required": True,
    "adoption_posture": "required",
}


@router.get("/policy")
async def get_policy():
    """Return the Requester's local policy (Section 7.7)."""
    return POLICY


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def verify_pa(
    pa: Dict[str, Any],
    challenge_nonce: Optional[str],
    aud: Optional[str],
    policy: Dict[str, Any],
) -> List[str]:
    """
    Run every verification rule the Requester MUST perform per the draft.
    Returns a list of structured reason codes; empty means PA is valid.
    """
    reasons: List[str] = []

    # Section 5.7 - signature verification
    sig = pa.get("sig")
    if not sig:
        reasons.append("PA_UNSIGNED")
        return reasons
    payload = {k: v for k, v in pa.items() if k != "sig"}
    if not C.verify_with_issuer(pa.get("iss", ""), C.jcs_canonical(payload), sig):
        reasons.append("PA_BAD_SIGNATURE")
        return reasons

    # iat / exp
    if pa.get("exp", 0) < C.now() - 5:
        reasons.append("PA_EXPIRED")
    if pa.get("iat", 0) > C.now() + 300:
        reasons.append("PA_IAT_FUTURE")
    if C.now() - pa.get("iat", 0) > policy.get("max_pa_age_seconds", 3600):
        reasons.append("PA_STALE")

    # Section 5.5 - challenge binding
    if challenge_nonce is not None:
        bind = pa.get("bind") or {}
        if bind.get("method") != "nonce_hash":
            reasons.append("PA_BIND_METHOD_UNSUPPORTED")
        else:
            expected = C.sha256_b64url(challenge_nonce.encode())
            if bind.get("nonce") != expected:
                reasons.append("PA_BIND_MISMATCH")

    # Issuer trust
    if pa.get("iss") not in policy.get("issuers_allowed", []):
        reasons.append("ISSUER_UNTRUSTED")

    # Framework anchoring (Section 5.2 rule 4 - byte-equal URI compare)
    fid = pa.get("framework_id", "")
    if fid not in policy.get("frameworks_allowed", []):
        reasons.append("FRAMEWORK_UNRECOGNIZED")
    else:
        tier_min = policy.get("tier_min_by_framework", {}).get(fid, 99)
        if pa.get("tier", 0) < tier_min:
            reasons.append("TIER_TOO_LOW")

    # Methodology gating
    method = (pa.get("claims") or {}).get("assessment_method")
    if method not in policy.get("assessment_method_allowed", []):
        reasons.append("POLICY_METHOD_MISMATCH")

    # Section 11 enrollment cap - self-attested capped at tier 1
    if (
        pa.get("enrollment_mode") == "self"
        and policy.get("enrollment_mode_min") == "assessed"
        and pa.get("tier", 0) > 1
    ):
        reasons.append("ENROLLMENT_MODE_INSUFFICIENT")

    return reasons


@router.post("/verify-pa")
async def verify_pa_endpoint(
    pa: Dict[str, Any],
    challenge_nonce: Optional[str] = None,
    aud: Optional[str] = None,
):
    """Standalone PA verifier - useful for replaying a PA from the broken track."""
    reasons = verify_pa(pa, challenge_nonce, aud, POLICY)
    return {"valid": not reasons, "reasons": reasons}


# ---------------------------------------------------------------------------
# Negotiation
# ---------------------------------------------------------------------------


@router.post("/proof")
async def submit_proof_secure(req: C.ProofRequest, request: Request):
    """
    Spec-conformant Negotiation. Verifies signature, challenge binding,
    issuer trust, framework + tier, methodology, enrollment cap, and binds
    the issued Permit to the transport channel.
    """
    ch = C.active_challenges.get(req.challenge_id)
    if ch is None:
        raise HTTPException(status_code=404, detail="challenge not found")

    reasons = verify_pa(
        req.pa,
        challenge_nonce=ch["challenge_nonce"],
        aud=ch.get("aud"),
        policy=POLICY,
    )
    if reasons:
        return {
            "decision": "DENY",
            "reasons": reasons,
            "required_improvements": "see Section 5 / 11",
        }

    peer = request.client.host if request.client else "unknown"
    ch_context = C.sha256_b64url(
        (peer + "|" + ch["challenge_id"] + "|" + ch["challenge_nonce"]).encode()
    )

    pa = req.pa
    constraints = {
        "actions": list(set((pa.get("scope") or {}).get("actions", ["read"]))),
        "data": list(set((pa.get("scope") or {}).get("data", ["internal"]))),
        "ttl": min(300, pa.get("exp", 0) - C.now()),
    }
    permit_id = f"permit_{C.b64url(C.sha256_b64url(req.challenge_id.encode()).encode())[:16]}"
    permit = {
        "permit_id": permit_id,
        "iss": "requester:secure",
        "sub": pa["sub"],
        "iat": C.now(),
        "exp": C.now() + min(300, pa["exp"] - C.now()),
        "constraints": constraints,
        "framework_id": pa["framework_id"],
        "tier": pa["tier"],
        "flags": (pa.get("claims") or {}).get("flags", {}),
        "ch_binding": {"method": "tls-exporter-equiv", "context_hash": ch_context},
        "pa_jti": pa["jti"],
    }
    permit["sig"] = C.sign_with_issuer(
        "https://issuer-strict.example", C.jcs_canonical(permit)
    )
    C.issued_permits[permit_id] = permit
    return {"decision": "PERMIT", "permit": permit}


@router.get("/permits/{permit_id}/validate")
async def validate_permit_secure(
    permit_id: str,
    request: Request,
    x_challenge_id: Optional[str] = Header(None),
):
    """
    Verifies Permit signature AND channel binding context. A Permit lifted to
    a different peer's channel cannot be reused.
    """
    permit = C.issued_permits.get(permit_id)
    if permit is None:
        raise HTTPException(status_code=404, detail="not found")

    payload = {k: v for k, v in permit.items() if k != "sig"}
    if not C.verify_with_issuer(
        "https://issuer-strict.example", C.jcs_canonical(payload), permit.get("sig", "")
    ):
        return {"valid": False, "reason": "PERMIT_BAD_SIGNATURE"}

    if permit["exp"] < C.now():
        return {"valid": False, "reason": "PERMIT_EXPIRED"}

    ch_binding = permit.get("ch_binding") or {}
    if not ch_binding.get("context_hash"):
        return {"valid": False, "reason": "CH_BINDING_MISSING"}

    ch = C.active_challenges.get(x_challenge_id or "")
    peer = request.client.host if request.client else "unknown"
    if ch is None:
        return {"valid": False, "reason": "CH_BINDING_NO_CHALLENGE_HEADER"}
    expected = C.sha256_b64url(
        (peer + "|" + ch["challenge_id"] + "|" + ch["challenge_nonce"]).encode()
    )
    if expected != ch_binding["context_hash"]:
        return {"valid": False, "reason": "CH_BINDING_MISMATCH"}

    return {"valid": True, "permit": permit}
