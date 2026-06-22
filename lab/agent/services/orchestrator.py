"""
Orchestrator - middle agent that wraps a delegation layer reducing scope
from the root intent before passing the chain to the worker.

Two endpoints:

  POST /delegate-honest  - reduces scope strictly (subset of parent)
  POST /delegate-broken  - allows arbitrary scope_reduction (mid-chain
                           expansion attack)

A solution-track tool gate rejects the broken delegation as
DEL_CHAIN_SCOPE_EXPANDED. A broken-track tool gate accepts it.
"""

from typing import Any, Dict

from fastapi import FastAPI
from pydantic import BaseModel

from shared.atp import KeyPair, wrap_delegation
from shared.peer import prime_cache


SERVICE = "orchestrator"

ORCH_KEY = KeyPair(SERVICE)
prime_cache(SERVICE, ORCH_KEY.public)


app = FastAPI(title=f"ATP Lab - {SERVICE}")


class DelegateRequest(BaseModel):
    inner_jws: str
    delegatee: str
    scope_reduction: Dict[str, Any]
    ttl_seconds: int = 300


@app.get("/.well-known/atp-pubkey")
async def well_known_pubkey() -> Dict[str, Any]:
    return {"kid": SERVICE, "alg": "EdDSA", "public_key": ORCH_KEY.public_b64url}


@app.post("/delegate-honest")
async def delegate_honest(req: DelegateRequest) -> Dict[str, Any]:
    """Wrap a delegation layer. Caller is expected to pass a strictly-reduced
    scope. (No signing-time enforcement here on purpose; the lab demonstrates
    receiver-side enforcement at the tool gate.)"""
    chain = wrap_delegation(
        ORCH_KEY,
        delegatee=req.delegatee,
        scope_reduction=req.scope_reduction,
        inner_jws=req.inner_jws,
        ttl_seconds=req.ttl_seconds,
    )
    return {"chain_jws": chain}


@app.post("/delegate-broken")
async def delegate_broken(req: DelegateRequest) -> Dict[str, Any]:
    """Same as delegate-honest mechanically. Exposed as a separate endpoint
    so the driver can label the call site clearly when constructing an
    expanded-scope chain. Receiver enforcement (Section 3.4) is what
    catches this regardless of which signing endpoint was used."""
    chain = wrap_delegation(
        ORCH_KEY,
        delegatee=req.delegatee,
        scope_reduction=req.scope_reduction,
        inner_jws=req.inner_jws,
        ttl_seconds=req.ttl_seconds,
    )
    return {"chain_jws": chain, "warning": "scope_reduction was not validated at signing time"}


@app.get("/health")
async def health():
    return {"service": SERVICE, "status": "ok"}
