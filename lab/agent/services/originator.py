"""
Originator - the human user (e.g. Alice). Holds an Ed25519 root signing key
and signs root Intents. In the lab the Originator is its own service so the
trust boundary is a process boundary - no other principal has access to the
private signing key.
"""

from typing import Any, Dict, List

from fastapi import FastAPI
from pydantic import BaseModel

from shared.atp import KeyPair, build_root_intent
from shared.peer import prime_cache


SERVICE = "originator"

ORIG_KEY = KeyPair(SERVICE)
prime_cache(SERVICE, ORIG_KEY.public)


app = FastAPI(title=f"ATP Lab - {SERVICE}")


class SignIntentRequest(BaseModel):
    intent_object: Dict[str, Any]
    authorized_chain: List[str]
    ttl_seconds: int = 600


@app.get("/.well-known/atp-pubkey")
async def well_known_pubkey() -> Dict[str, Any]:
    return {"kid": SERVICE, "alg": "EdDSA", "public_key": ORIG_KEY.public_b64url}


@app.post("/sign-intent")
async def sign_intent(req: SignIntentRequest) -> Dict[str, Any]:
    """The single human-consented signing event. In production this is the
    'user signs what user sees' UI; in the lab it's a tightly-scoped POST."""
    return build_root_intent(
        ORIG_KEY,
        intent_object=req.intent_object,
        authorized_chain=req.authorized_chain,
        ttl_seconds=req.ttl_seconds,
    )


@app.get("/health")
async def health():
    return {"service": SERVICE, "status": "ok"}
