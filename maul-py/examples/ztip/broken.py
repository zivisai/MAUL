"""
ZTIP - BROKEN track.

Vulnerabilities (mapped to draft sections):

  V1  Chain layer signatures not verified                  (Section 3.3 rule 1)
  V2  Scope monotonicity not enforced                       (Section 3.4)
  V3  intent_hash not recomputed; confused deputy           (Section 4)
  V4  No chain depth cap; resource exhaustion               (Section 3.5)
  V5  Operation classification spoofing                     (Section 4.3)
  V7  Untrusted Originator accepted as chain root           (Section 3.3 rule 4)

Routes are mounted under /api/examples/ztip/broken/...
"""

from fastapi import APIRouter, HTTPException

from . import _common as C


router = APIRouter(
    prefix="/api/examples/ztip/broken",
    tags=["ZTIP - BROKEN"],
)


@router.post("/intent/sign")
async def sign_intent(req: C.SignIntentRequest):
    """Originator signs root Intent. Anyone can call - no auth."""
    try:
        return C.build_signed_intent(req)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/chain/wrap")
async def wrap_layer(req: C.DelegationLayerRequest):
    """V2/V4: no scope-reduction enforcement at signing time, no depth cap."""
    try:
        return C.wrap_delegation(req)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/chain/verify")
async def verify_chain(jws: str):
    """V1/V2/V3/V4/V7: parses chain, no checks."""
    layers = []
    cur = jws
    while True:
        try:
            _h, p = C.parse_jws_unverified(cur)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"malformed jws: {e}")
        layers.append(p)
        if p.get("intent_root"):
            break
        cur = p.get("inner")
        if not cur:
            break
    return {
        "valid": True,
        "depth": len(layers),
        "layers": layers,
        "warning": "no signature, scope, depth, or originator-trust checks performed",
    }


@router.post("/token/intent-scoped")
async def issue_intent_scoped_token(req: C.IssueIntentScopedTokenRequest):
    """V3: intent_hash copied from chain root claim, never recomputed."""
    cur = req.chain_jws
    while True:
        _h, p = C.parse_jws_unverified(cur)
        if p.get("intent_root"):
            root = p
            break
        cur = p.get("inner")
        if cur is None:
            raise HTTPException(status_code=400, detail="no root intent")
    token = {
        "iss": "broken-as.example",
        "sub": "agent:bearer",
        "aud": "tool:any",
        "iat": C.now(),
        "exp": C.now() + 600,
        "scope": req.scope,
        "intent_hash": root.get("intent_hash"),
        "intent_scope": root.get("scope", {}),
        "chain_root_iss": root.get("originator"),
        "chain_root_jti": root.get("jti"),
    }
    return {"token": token}


@router.post("/operation/gate")
async def gate_operation(req: C.GateOperationRequest):
    """V3/V5: trusts AS-issued `scope`; no intent_hash recomputation."""
    op = req.operation
    scope = req.token.get("scope") or req.token.get("intent_scope") or {}
    actions_ok = ("actions" not in scope) or (op.get("action") in scope["actions"])
    tools_ok = ("tools" not in scope) or (op.get("tool") in scope["tools"])
    return {
        "decision": "ALLOW" if (actions_ok and tools_ok) else "DENY_BY_SCOPE",
        "reason": "broken gate trusts AS-issued scope; no intent_hash recomputation",
    }


@router.post("/behavioral/issue")
async def issue_behavioral_credential(req: C.BehavioralClaimsRequest):
    """Issue a credential carrying ZTIP behavioral claims (Section 5).
    Broken: accepts bare booleans without evidence."""
    if req.issuer not in {p["id"] for p in C.all_principals()}:
        raise HTTPException(status_code=400, detail="unknown issuer")
    payload = {
        "iss": req.issuer,
        "sub": req.subject,
        "iat": C.now(),
        "exp": C.now() + req.ttl_seconds,
        "ai_behavior": {
            **req.claims,
            **({"evidence": req.evidence} if req.evidence else {}),
        },
    }
    jws = C.compact_jws(req.issuer, payload)
    return {"credential_jws": jws, "payload": payload}
