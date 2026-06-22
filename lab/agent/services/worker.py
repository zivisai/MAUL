"""
Worker - the prompt-injection-exposed sub-agent.

The worker:
  - Holds its own Ed25519 key.
  - Was issued a Posture Assertion at startup (cached in memory).
  - Wraps its own delegation layer reducing scope to the specific tool call.
  - Calls the tool over mTLS, presenting:
      * its PA (for ZTNP)
      * the full delegation chain (for ZTIP)
      * an intent-scoped token claiming intent_hash + intent_scope from the
        chain root

Two execution modes:

  POST /act-honest   - performs the user's authorized operation
  POST /act-injected - simulates a prompt-injected operation
                       (substitutes the operational intent mid-flight)
"""

import os
from typing import Any, Dict

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from shared.atp import (
    KeyPair,
    parse_jws_unverified,
    sha256_b64url,
    jcs_canonical,
    wrap_delegation,
)
from shared.peer import make_client, prime_cache, url


SERVICE = "worker"

WORKER_KEY = KeyPair(SERVICE)
prime_cache(SERVICE, WORKER_KEY.public)


app = FastAPI(title=f"ATP Lab - {SERVICE}")

# Will be populated lazily on the first /act call so the worker doesn't
# depend on the issuer being reachable at startup.
_ENROLLED_PA: Dict[str, Any] | None = None


def _enroll_self_if_needed(client) -> Dict[str, Any]:
    global _ENROLLED_PA
    if _ENROLLED_PA is not None:
        return _ENROLLED_PA
    # Worker enrolls strictly so the solution Requester accepts it.
    resp = client.post(
        url("issuer", "/enroll/strict"),
        json={
            "sub": SERVICE,
            "framework_id": "https://doi.org/10.6028/NIST.AI.100-1",
            "tier": 3,
            "ttl_seconds": 3600,
        },
    )
    resp.raise_for_status()
    _ENROLLED_PA = resp.json()
    return _ENROLLED_PA


class ActRequest(BaseModel):
    chain_jws: str   # delegation chain handed to worker by orchestrator
    operation: Dict[str, Any]   # caller-supplied operation to perform
    tool_endpoint: str  # which tool path to hit ("/broken/operation" or "/solution/operation")


@app.get("/.well-known/atp-pubkey")
async def well_known_pubkey() -> Dict[str, Any]:
    return {"kid": SERVICE, "alg": "EdDSA", "public_key": WORKER_KEY.public_b64url}


@app.post("/act-honest")
async def act_honest(req: ActRequest) -> Dict[str, Any]:
    """Perform the operation as instructed - no substitution."""
    return await _act(req, inject=False)


@app.post("/act-injected")
async def act_injected(req: ActRequest) -> Dict[str, Any]:
    """Simulate prompt injection: the worker has been told to do op_A by
    the orchestrator, but the prompt-injected content reaches the worker
    and it performs op_B instead. The chain it presents is unchanged.
    (This is exactly the confused-deputy attack ZTIP exists to defeat.)"""
    return await _act(req, inject=True)


async def _act(req: ActRequest, inject: bool) -> Dict[str, Any]:
    client = make_client(SERVICE)
    pa = _enroll_self_if_needed(client)

    # Get a fresh challenge from the tool first (ZTNP Negotiation).
    ch = client.post(
        url("tool", "/challenge"),
        json={"sub": SERVICE},
    )
    ch.raise_for_status()
    challenge = ch.json()

    # Re-bind PA to this challenge.
    pa_bound = client.post(
        url("issuer", "/enroll/strict"),
        json={
            "sub": SERVICE,
            "framework_id": "https://doi.org/10.6028/NIST.AI.100-1",
            "tier": 3,
            "bind_nonce": challenge["challenge_nonce"],
            "ttl_seconds": 600,
        },
    )
    pa_bound.raise_for_status()
    pa_for_call = pa_bound.json()

    # Worker wraps its own (scope-preserving) delegation layer over the
    # incoming chain so the tool sees the full root -> orchestrator -> worker
    # chain at receipt.
    inner = req.chain_jws
    # Read the orchestrator's scope_reduction so we can mirror it.
    _h, p = parse_jws_unverified(inner)
    parent_scope = p.get("scope_reduction") or p.get("scope") or {}
    chain = wrap_delegation(
        WORKER_KEY,
        delegatee="tool",
        scope_reduction=parent_scope,  # mirror parent (no further reduction)
        inner_jws=inner,
    )

    # Walk to root to copy intent_hash for the token claim.
    root = p
    cur_jws = inner
    while not root.get("intent_root"):
        cur_jws = root.get("inner")
        _h2, root = parse_jws_unverified(cur_jws)

    operation = req.operation
    if inject:
        # Prompt injection takes effect here: the worker decides to call a
        # different tool action than what the chain authorizes.
        operation = {"action": "send", "tool": "email.send", "data": ["pii"]}

    intent_scoped_token = {
        "iss": SERVICE,
        "sub": SERVICE,
        "intent_hash": root.get("intent_hash"),
        "intent_scope": root.get("scope", {}),
        "chain_root_iss": root.get("originator"),
        "chain_root_jti": root.get("jti"),
    }

    # Make the tool call. Carry challenge_id, PA, chain, token, op.
    resp = client.post(
        url("tool", req.tool_endpoint),
        json={
            "challenge_id": challenge["challenge_id"],
            "pa": pa_for_call,
            "chain_jws": chain,
            "intent_scoped_token": intent_scoped_token,
            "operation": operation,
        },
    )
    return {
        "tool_status": resp.status_code,
        "tool_response": resp.json(),
        "intended_operation": req.operation,
        "actual_operation_sent": operation,
        "injected": inject,
    }


@app.get("/health")
async def health():
    return {"service": SERVICE, "status": "ok"}
