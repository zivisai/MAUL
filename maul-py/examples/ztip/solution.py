"""
ZTIP - SOLUTION track.

A spec-conformant implementation of draft-miller-ztip-00. Each verification
rule cites the section it implements.

Routes are mounted under /api/examples/ztip/solution/...
"""

import json
import time
from typing import Any, Dict, List, Tuple

from fastapi import APIRouter

from . import _common as C


router = APIRouter(
    prefix="/api/examples/ztip/solution",
    tags=["ZTIP - SOLUTION"],
)


SECURE_MAX_DEPTH = 8


def verify_chain(
    jws: str, max_depth: int = SECURE_MAX_DEPTH
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Verify a Delegation Chain per Section 3.3:
      Rule 1 - signature on every layer
      Rule 2 - delegator/delegatee chain unbroken
      Rule 3 - scope monotonicity (Section 3.4)
      Rule 4 - root signed by trusted Originator
      Rule 5 - no layer expired
      Rule 6 - depth check (Section 3.5) BEFORE signature work
      Rule 7 - intent_hash recomputed and compared

    Returns (layers_outermost_first, reason_codes).
    """
    reasons: List[str] = []

    # Rule 6 first - depth check before any signature work
    depth = 0
    probe = jws
    while True:
        depth += 1
        if depth > max_depth:
            return [], ["DEL_CHAIN_DEPTH_EXCEEDED"]
        try:
            _h, p = C.parse_jws_unverified(probe)
        except Exception:
            return [], ["DEL_CHAIN_BROKEN"]
        if p.get("intent_root"):
            break
        probe = p.get("inner")
        if not probe:
            return [], ["DEL_CHAIN_BROKEN"]

    # Rules 1 + 5 - verify each layer's signature and freshness
    layers: List[Dict[str, Any]] = []
    cur = jws
    while True:
        try:
            ok, _header, payload = C.verify_jws(cur)
        except Exception:
            return [], ["DEL_CHAIN_BROKEN"]
        if not ok:
            return [], ["DEL_CHAIN_BAD_SIGNATURE"]
        if payload.get("exp", 0) < C.now() - 5:
            return [], ["DEL_CHAIN_EXPIRED"]
        layers.append(payload)
        if payload.get("intent_root"):
            break
        cur = payload.get("inner")
        if not cur:
            return [], ["DEL_CHAIN_BROKEN"]

    root = layers[-1]

    # Rule 4 - root must be from a trusted Originator
    rec = C.principal_record(root.get("originator", ""))
    if rec is None or not rec.get("trusted_originator"):
        return [], ["DEL_CHAIN_UNTRUSTED_ROOT"]

    # Rule 7 - intent_hash recomputed
    canonical = C.jcs_canonical(root.get("intent_object") or {})
    if C.sha256_b64url(canonical) != root.get("intent_hash"):
        return [], ["INTENT_HASH_MISMATCH_ROOT"]

    # Rules 2 + 3 - walk root -> outermost
    parent_scope = root.get("scope", {})
    parent_principal = root.get("originator")
    authorized = root.get("authorized_chain", [])
    for layer in reversed(layers[:-1]):
        if layer.get("delegator") != parent_principal and layer.get(
            "delegator"
        ) not in authorized:
            return [], ["DEL_CHAIN_BROKEN"]
        violation = C.scope_subset_violation(
            parent_scope, layer.get("scope_reduction", {})
        )
        if violation is not None:
            return [], ["DEL_CHAIN_SCOPE_EXPANDED", json.dumps(violation)]
        parent_scope = layer.get("scope_reduction", {})
        parent_principal = layer.get("delegatee")

    return layers, reasons


@router.post("/chain/verify")
async def verify_chain_endpoint(jws: str):
    layers, reasons = verify_chain(jws)
    if reasons:
        return {"valid": False, "reasons": reasons}
    return {"valid": True, "depth": len(layers), "layers": layers}


@router.post("/operation/gate")
async def gate_operation(req: C.GateOperationRequest):
    """
    Spec-conformant gate (Section 4.2):
      1. Determine the operation's (action, data_classes, tool) signature.
      2. Verify operation falls within intent_scope.
      3. Recompute intent_hash from the chain root and compare to token.

    The token MAY embed `chain_jws` so the verifier can recompute. Otherwise
    the verifier accepts a token whose `intent_object` is present and whose
    `intent_hash` matches a recomputed JCS hash of it.
    """
    token = req.token
    op = req.operation
    intent_scope = token.get("intent_scope", {}) or {}
    intent_hash_claim = token.get("intent_hash")

    chain_jws = token.get("chain_jws")
    if chain_jws:
        layers, reasons = verify_chain(chain_jws)
        if reasons:
            return {
                "decision": "DENY",
                "reason": "INTENT_SCOPE_MISMATCH",
                "details": reasons,
            }
        root = layers[-1]
        recomputed = C.sha256_b64url(C.jcs_canonical(root.get("intent_object") or {}))
        if recomputed != intent_hash_claim:
            return {"decision": "DENY", "reason": "INTENT_SCOPE_MISMATCH"}
        intent_scope = root.get("scope") or intent_scope
    elif token.get("intent_object") is not None:
        recomputed = C.sha256_b64url(C.jcs_canonical(token["intent_object"]))
        if recomputed != intent_hash_claim:
            return {"decision": "DENY", "reason": "INTENT_SCOPE_MISMATCH"}

    if "actions" in intent_scope and op.get("action") not in intent_scope["actions"]:
        return {
            "decision": "DENY",
            "reason": "INTENT_SCOPE_MISMATCH",
            "field": "action",
        }
    if "tools" in intent_scope and op.get("tool") not in intent_scope["tools"]:
        return {"decision": "DENY", "reason": "INTENT_SCOPE_MISMATCH", "field": "tool"}
    if "data" in intent_scope:
        for d in op.get("data", []):
            if d not in intent_scope["data"]:
                return {
                    "decision": "DENY",
                    "reason": "INTENT_SCOPE_MISMATCH",
                    "field": "data",
                    "value": d,
                }
    return {"decision": "ALLOW"}


@router.post("/behavioral/check")
async def check_behavioral(credential_jws: str, claim_required: str):
    """
    Section 5.1.1 - require:
      - signature
      - the named claim
      - an evidence entry naming a public corpus or carrying evidence_hash
      - non-expired evidence (validity_days)
    """
    ok, _h, payload = C.verify_jws(credential_jws)
    if not ok:
        return {"accepted": False, "reason": "BEHAVIORAL_BAD_SIGNATURE"}
    ai = payload.get("ai_behavior", {})
    if not ai.get(claim_required):
        return {"accepted": False, "reason": "BEHAVIORAL_CLAIM_MISSING"}
    evidence = (ai.get("evidence") or {}).get(claim_required)
    if not evidence:
        return {"accepted": False, "reason": "BEHAVIORAL_EVIDENCE_MISSING"}
    method = evidence.get("method", "")
    if not (method.startswith("owasp_llm_top10_") or evidence.get("evidence_hash")):
        return {"accepted": False, "reason": "BEHAVIORAL_EVIDENCE_NOT_PUBLIC"}
    if evidence.get("validity_days") is not None:
        try:
            from datetime import datetime as _dt

            d = _dt.strptime(evidence["date"], "%Y-%m-%d")
            age_days = (time.time() - d.timestamp()) / 86400
            if age_days > evidence["validity_days"]:
                return {"accepted": False, "reason": "BEHAVIORAL_EVIDENCE_EXPIRED"}
        except Exception:
            return {"accepted": False, "reason": "BEHAVIORAL_EVIDENCE_BAD_DATE"}
    return {"accepted": True, "evidence": evidence}
