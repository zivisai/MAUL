"""
Issuer - signs Posture Assertions (ZTNP) and publishes its IKS over HTTPS.

In the lab the Issuer is a third-party assessor. It exposes two distinct
enrollment endpoints to demonstrate the policy gap:

  POST /enroll/strict   - emits assessed/human_review PAs (acceptable)
  POST /enroll/loose    - emits self/self_attestation PAs (not acceptable
                          to a well-configured Requester)

Both produce real Ed25519 signatures over the same payload format.

The IKS endpoint at /iks publishes the issuer's public key. mTLS-enforced.
"""

from typing import Dict, Any

from fastapi import FastAPI
from pydantic import BaseModel

from shared.atp import KeyPair, build_signed_pa
from shared.peer import prime_cache


SERVICE = "issuer"

ISSUER_KEY = KeyPair(SERVICE)
prime_cache(SERVICE, ISSUER_KEY.public)

FRAMEWORKS = [
    "https://doi.org/10.6028/NIST.AI.100-1",
    "https://www.iso.org/standard/81230.html",
    "https://genai.owasp.org/llm-top-10/2025",
]


app = FastAPI(title=f"ATP Lab - {SERVICE}")


class EnrollRequest(BaseModel):
    sub: str
    framework_id: str
    tier: int
    bind_nonce: str | None = None
    ttl_seconds: int = 3600


@app.get("/.well-known/atp-pubkey")
async def well_known_pubkey() -> Dict[str, Any]:
    return {"kid": SERVICE, "alg": "EdDSA", "public_key": ISSUER_KEY.public_b64url}


@app.get("/iks")
async def iks() -> Dict[str, Any]:
    """Issuer Key Set (Section 6 of ZTNP)."""
    return {
        "iss": SERVICE,
        "frameworks": FRAMEWORKS,
        "keys": [
            {
                "kid": SERVICE,
                "alg": "EdDSA",
                "kty": "OKP",
                "crv": "Ed25519",
                "x": ISSUER_KEY.public_b64url,
            }
        ],
    }


@app.post("/enroll/strict")
async def enroll_strict(req: EnrollRequest) -> Dict[str, Any]:
    """Issue an assessed/human_review PA (acceptable to a strict Requester)."""
    return build_signed_pa(
        ISSUER_KEY,
        sub=req.sub,
        framework_id=req.framework_id,
        tier=req.tier,
        enrollment_mode="assessed",
        assessment_method="human_review",
        bind_nonce=req.bind_nonce,
        ttl_seconds=req.ttl_seconds,
    )


@app.post("/enroll/loose")
async def enroll_loose(req: EnrollRequest) -> Dict[str, Any]:
    """Issue a self/self_attestation PA (rejected by Section 11 cap)."""
    return build_signed_pa(
        ISSUER_KEY,
        sub=req.sub,
        framework_id=req.framework_id,
        tier=req.tier,  # caller picks any tier - solution Requester caps at 1
        enrollment_mode="self",
        assessment_method="self_attestation",
        bind_nonce=req.bind_nonce,
        ttl_seconds=req.ttl_seconds,
    )


@app.get("/health")
async def health():
    return {"service": SERVICE, "status": "ok"}
