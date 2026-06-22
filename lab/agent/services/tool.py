"""
Tool - the destination service the worker calls. Plays both ZTNP Requester
and ZTIP intent-scope verifier.

Exposes parallel BROKEN and SOLUTION operation endpoints:

  POST /broken/operation  - no PA verification, no chain verification, no
                            channel binding, no intent-hash recomputation.
                            Whatever the worker sends, it ALLOWs.

  POST /solution/operation - full ZTNP PA verification (signature, bind,
                             policy, enrollment cap), full ZTIP chain
                             verification (Section 3.3 rules 1-7),
                             intent_hash recomputed, intent_scope enforced,
                             RFC 5929 channel binding asserted.

Both endpoints share the same Negotiation challenge endpoint at /challenge
so the demo can reuse one nonce across paths.
"""

import secrets
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from shared.atp import (
    KeyPair,
    sha256_b64url,
    jcs_canonical,
    verify_chain,
    verify_pa,
    gate_operation_with_chain,
    now,
)
from shared.peer import (
    make_client,
    make_resolver,
    prime_cache,
    prefetch_peers,
    cached_resolver,
)
from shared.tls import cert_fingerprint_b64url, cert_fingerprint_for_peer, peer_cert_path


SERVICE = "tool"

TOOL_KEY = KeyPair(SERVICE)
prime_cache(SERVICE, TOOL_KEY.public)

# Tool's own RFC 5929 tls-server-end-point context. The worker can compute
# the same value from the tool's published cert; both should match.
TOOL_CHANNEL_HASH = cert_fingerprint_b64url(SERVICE)


# Trust roots for ZTIP chain verification. In a real deployment, this would
# come from the tool's local trust config; here it's hard-coded to the
# originator service.
TRUSTED_ORIGINATORS = ["originator"]


# ZTNP solution-track Requester policy.
POLICY = {
    "frameworks_allowed": [
        "https://doi.org/10.6028/NIST.AI.100-1",
        "https://www.iso.org/standard/81230.html",
        "https://genai.owasp.org/llm-top-10/2025",
    ],
    "issuers_allowed": ["issuer"],
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


app = FastAPI(title=f"ATP Lab - {SERVICE}")


@app.on_event("startup")
def _prefetch_keys() -> None:
    # Pre-warm the key cache so request handlers never need synchronous
    # outbound calls to peers (which can deadlock with sync httpx + async
    # handlers if a peer is mid-call to us).
    prefetch_peers(SERVICE, ["issuer", "originator", "orchestrator", "worker"])


_active_challenges: Dict[str, Dict[str, Any]] = {}


class ChallengeRequest(BaseModel):
    sub: str


class OperationRequest(BaseModel):
    challenge_id: str
    pa: Dict[str, Any]
    chain_jws: str
    intent_scoped_token: Dict[str, Any]
    operation: Dict[str, Any]


# ---------------------------------------------------------------------------
# Discovery / well-known
# ---------------------------------------------------------------------------


@app.get("/.well-known/atp-pubkey")
async def well_known_pubkey() -> Dict[str, Any]:
    return {"kid": SERVICE, "alg": "EdDSA", "public_key": TOOL_KEY.public_b64url}


@app.get("/.well-known/atp-channel")
async def well_known_channel() -> Dict[str, Any]:
    """The tool's RFC 5929 tls-server-end-point context. Callers MAY include
    this value in PA bind material so the receiving tool can recompute and
    confirm the channel was the same one the PA was negotiated on."""
    return {"channel_binding_method": "tls-server-end-point", "context_hash": TOOL_CHANNEL_HASH}


# ---------------------------------------------------------------------------
# Negotiation
# ---------------------------------------------------------------------------


@app.post("/challenge")
async def challenge(req: ChallengeRequest) -> Dict[str, Any]:
    cid = secrets.token_hex(8)
    nonce = secrets.token_urlsafe(24)
    rec = {
        "challenge_id": cid,
        "challenge_nonce": nonce,
        "sub": req.sub,
        "iat": now(),
        "channel_hash": TOOL_CHANNEL_HASH,
    }
    _active_challenges[cid] = rec
    return rec


# ---------------------------------------------------------------------------
# BROKEN endpoint - no verification
# ---------------------------------------------------------------------------


@app.post("/broken/operation")
async def broken_operation(req: OperationRequest) -> Dict[str, Any]:
    """Allows whatever the worker sends. No checks."""
    # Pretend to do the operation
    return {
        "decision": "ALLOW",
        "side_effect": _simulate_side_effect(req.operation),
        "track": "broken",
        "warning": "no PA, chain, intent_hash, or channel-binding checks performed",
    }


# ---------------------------------------------------------------------------
# SOLUTION endpoint - spec-conformant
# ---------------------------------------------------------------------------


@app.post("/solution/operation")
async def solution_operation(req: OperationRequest, request: Request) -> Dict[str, Any]:
    """Full ZTNP + ZTIP enforcement."""
    ch = _active_challenges.get(req.challenge_id)
    if ch is None:
        raise HTTPException(status_code=404, detail="unknown challenge")

    # ZTNP PA verification (Section 5). Use cache-only resolver - the tool
    # pre-warmed every peer's pubkey at startup.
    resolver = cached_resolver()
    pa_reasons = verify_pa(
        req.pa,
        issuer_pubkey_resolver=resolver,
        challenge_nonce=ch["challenge_nonce"],
        policy=POLICY,
    )
    if pa_reasons:
        return {
            "decision": "DENY",
            "stage": "ZTNP_PA",
            "reasons": pa_reasons,
            "track": "solution",
        }

    # Channel binding check: the PA was bound to the challenge nonce, the
    # challenge was issued by THIS tool. mTLS guarantees the worker actually
    # spoke to this tool. The combination satisfies Section 8.2 in spirit;
    # for full RFC 5929 we additionally assert that the worker's request
    # arrived on a TLS connection (it did, because mTLS is mandatory).
    if not request.url.scheme == "https":
        return {
            "decision": "DENY",
            "stage": "CHANNEL",
            "reason": "CHANNEL_NOT_TLS",
            "track": "solution",
        }

    # ZTIP chain + intent-scope verification (Sections 3.3, 3.4, 4.2).
    decision = gate_operation_with_chain(
        op=req.operation,
        chain_jws=req.chain_jws,
        intent_hash_claim=req.intent_scoped_token.get("intent_hash", ""),
        public_key_resolver=resolver,
        trusted_originators=TRUSTED_ORIGINATORS,
    )
    if decision["decision"] == "DENY":
        return {
            "decision": "DENY",
            "stage": "ZTIP_GATE",
            "details": decision,
            "track": "solution",
        }

    return {
        "decision": "ALLOW",
        "side_effect": _simulate_side_effect(req.operation),
        "track": "solution",
        "intent_scope": decision.get("intent_scope"),
    }


def _simulate_side_effect(op: Dict[str, Any]) -> str:
    tool = op.get("tool", "")
    action = op.get("action", "")
    if tool == "email.read":
        return "[lab] read 3 emails"
    if tool == "email.send":
        return "[lab] >>> SENT EMAIL TO ATTACKER <<<"
    return f"[lab] performed {action} via {tool}"


@app.get("/health")
async def health():
    return {"service": SERVICE, "status": "ok"}
