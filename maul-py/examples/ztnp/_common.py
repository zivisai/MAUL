"""
ZTNP shared primitives - protocol mechanics that both the broken and
solution tracks need: signing keys, IKS state, JCS canonicalization,
JWS helpers, models. Nothing in here makes a security decision.

Reference: draft-miller-ztnp-00 (Sections 5, 6, 7, 8).
"""

import time
import json
import base64
import hashlib
import secrets
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    _CRYPTO_AVAILABLE = True
except Exception:  # pragma: no cover
    _CRYPTO_AVAILABLE = False


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def jcs_canonical(obj: Any) -> bytes:
    """
    Simplified JCS-style canonicalization (RFC 8785). Sufficient for the demo
    payloads in MAUL; production deployments MUST use a conformant JCS lib.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_b64url(data: bytes) -> str:
    return b64url(hashlib.sha256(data).digest())


def now() -> int:
    return int(time.time())


# ---------------------------------------------------------------------------
# Issuer Key Set (in-memory)
# ---------------------------------------------------------------------------
#
# Three issuers seeded:
#   issuer-strict.example   - rigorous third-party assessor
#   issuer-loose.example    - self-attestation issuer
#   issuer-attacker.example - rogue issuer

_issuer_keys: Dict[str, Dict[str, Any]] = {}


def _seed_issuer(iss: str, methodology: str, frameworks: List[str]) -> None:
    if not _CRYPTO_AVAILABLE:
        sk = secrets.token_bytes(32)
        _issuer_keys[iss] = {
            "iss": iss,
            "kid": f"{iss}#k1",
            "alg": "HS256",
            "private_bytes": sk,
            "public_bytes": sk,
            "methodology": methodology,
            "frameworks": frameworks,
        }
        return
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    _issuer_keys[iss] = {
        "iss": iss,
        "kid": f"{iss}#k1",
        "alg": "EdDSA",
        "private_key": sk,
        "public_key": pk,
        "private_bytes": sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        "public_bytes": pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
        "methodology": methodology,
        "frameworks": frameworks,
    }


_seed_issuer(
    "https://issuer-strict.example",
    methodology="human_review",
    frameworks=[
        "https://doi.org/10.6028/NIST.AI.100-1",
        "https://www.iso.org/standard/81230.html",
    ],
)
_seed_issuer(
    "https://issuer-loose.example",
    methodology="self_attestation",
    frameworks=["https://genai.owasp.org/llm-top-10/2025"],
)
_seed_issuer(
    "https://issuer-attacker.example",
    methodology="unspecified",
    frameworks=["https://nist.gov/airmf/1.0"],
)


def issuer_record(iss: str) -> Optional[Dict[str, Any]]:
    return _issuer_keys.get(iss)


def all_issuers() -> List[Dict[str, Any]]:
    return list(_issuer_keys.values())


def reseed_issuer(iss: str) -> None:
    """Rotate an issuer's keypair while preserving its methodology + frameworks."""
    old = _issuer_keys.get(iss)
    if old is None:
        return
    _seed_issuer(iss, methodology=old["methodology"], frameworks=old["frameworks"])


def sign_with_issuer(iss: str, payload: bytes) -> str:
    rec = _issuer_keys[iss]
    if rec["alg"] == "EdDSA":
        return b64url(rec["private_key"].sign(payload))
    import hmac

    return b64url(hmac.new(rec["private_bytes"], payload, hashlib.sha256).digest())


def verify_with_issuer(iss: str, payload: bytes, sig_b64url: str) -> bool:
    rec = _issuer_keys.get(iss)
    if rec is None:
        return False
    sig = b64url_decode(sig_b64url)
    try:
        if rec["alg"] == "EdDSA":
            rec["public_key"].verify(sig, payload)
            return True
        import hmac

        expected = hmac.new(rec["private_bytes"], payload, hashlib.sha256).digest()
        return hmac.compare_digest(expected, sig)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ChallengeRequest(BaseModel):
    sub: str
    framework_required: List[str] = Field(default_factory=list)
    mode: str = "PA-R"
    aud: Optional[str] = None


class IssuePARequest(BaseModel):
    iss: str
    sub: str
    framework_id: str
    tier: int
    enrollment_mode: str = "self"
    flags: Dict[str, bool] = Field(default_factory=dict)
    posture: Dict[str, Any] = Field(default_factory=dict)
    bind_nonce: Optional[str] = None
    ttl_seconds: int = 3600
    assessment_method: Optional[str] = None
    additional_frameworks: Optional[List[Dict[str, Any]]] = None


class ProofRequest(BaseModel):
    challenge_id: str
    pa: Dict[str, Any]


# ---------------------------------------------------------------------------
# Shared in-memory state
# ---------------------------------------------------------------------------

issued_pas: Dict[str, Dict[str, Any]] = {}
active_challenges: Dict[str, Dict[str, Any]] = {}
issued_permits: Dict[str, Dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# PA construction (used by both tracks)
# ---------------------------------------------------------------------------


def build_signed_pa(req: IssuePARequest) -> Dict[str, Any]:
    """
    Construct + sign a Posture Assertion.

    Note: this helper does NOT enforce Section 11's enrollment-mode tier cap;
    it produces whatever the caller asks for. The solution track applies the
    cap at verification time, while the broken track skips that check.
    """
    if req.iss not in _issuer_keys:
        raise ValueError("unknown issuer")
    pa_payload: Dict[str, Any] = {
        "ver": "0.2",
        "iss": req.iss,
        "sub": req.sub,
        "iat": now(),
        "exp": now() + req.ttl_seconds,
        "jti": f"pa_{secrets.token_hex(8)}",
        "framework_id": req.framework_id,
        "tier": req.tier,
        "scope": {"kind": "agent", "target": req.sub},
        "claims": {
            "flags": req.flags,
            "posture": req.posture,
            "assessment_method": req.assessment_method
            or _issuer_keys[req.iss]["methodology"],
        },
        "enrollment_mode": req.enrollment_mode,
    }
    if req.additional_frameworks:
        pa_payload["additional_frameworks"] = req.additional_frameworks
    if req.bind_nonce:
        pa_payload["bind"] = {
            "method": "nonce_hash",
            "nonce": sha256_b64url(req.bind_nonce.encode()),
        }
    pa_payload["sig"] = sign_with_issuer(req.iss, jcs_canonical(pa_payload))
    issued_pas[pa_payload["jti"]] = pa_payload
    return pa_payload


def issue_challenge_record(req: ChallengeRequest) -> Dict[str, Any]:
    cid = secrets.token_hex(8)
    nonce = secrets.token_urlsafe(24)
    rec = {
        "challenge_id": cid,
        "challenge_nonce": nonce,
        "framework_required": req.framework_required,
        "mode": req.mode,
        "aud": req.aud,
        "iat": now(),
    }
    active_challenges[cid] = rec
    return rec
