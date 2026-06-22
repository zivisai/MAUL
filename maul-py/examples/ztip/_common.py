"""
ZTIP shared primitives - protocol mechanics that both the broken and
solution tracks need: principal key registry, JCS, JWS helpers, models,
scope-monotonicity helper.

Reference: draft-miller-ztip-00 (Sections 3, 4, 5).
"""

import json
import hashlib
import secrets
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from examples.ztnp._common import (
    b64url,
    b64url_decode,
    jcs_canonical,
    sha256_b64url,
    now,
    _CRYPTO_AVAILABLE,
)

if _CRYPTO_AVAILABLE:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization


# ---------------------------------------------------------------------------
# Principal key registry
# ---------------------------------------------------------------------------
#
# Trusted Originators: alice, bob.
# Mallory exists and can sign, but is NOT a trusted Originator.
# Orchestrator/summarizer/worker/tools are intermediaries.

_principal_keys: Dict[str, Dict[str, Any]] = {}


def _seed_principal(pid: str, trusted_originator: bool = False) -> None:
    if not _CRYPTO_AVAILABLE:
        sk = secrets.token_bytes(32)
        _principal_keys[pid] = {
            "id": pid,
            "alg": "HS256",
            "private_bytes": sk,
            "public_bytes": sk,
            "trusted_originator": trusted_originator,
        }
        return
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    _principal_keys[pid] = {
        "id": pid,
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
        "trusted_originator": trusted_originator,
    }


_seed_principal("user:alice", trusted_originator=True)
_seed_principal("user:bob", trusted_originator=True)
_seed_principal("agent:orchestrator")
_seed_principal("agent:summarizer")
_seed_principal("agent:worker")
_seed_principal("user:mallory", trusted_originator=False)
_seed_principal("tool:email")
_seed_principal("tool:bank")


def principal_record(pid: str) -> Optional[Dict[str, Any]]:
    return _principal_keys.get(pid)


def all_principals() -> List[Dict[str, Any]]:
    return list(_principal_keys.values())


def sign_principal(pid: str, payload: bytes) -> str:
    rec = _principal_keys[pid]
    if rec["alg"] == "EdDSA":
        return b64url(rec["private_key"].sign(payload))
    import hmac

    return b64url(hmac.new(rec["private_bytes"], payload, hashlib.sha256).digest())


def verify_principal(pid: str, payload: bytes, sig_b64url: str) -> bool:
    rec = _principal_keys.get(pid)
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
# Compact JWS helpers
# ---------------------------------------------------------------------------


def compact_jws(principal: str, payload: Dict[str, Any]) -> str:
    header = {"alg": _principal_keys[principal]["alg"], "kid": principal}
    h64 = b64url(jcs_canonical(header))
    p64 = b64url(jcs_canonical(payload))
    signing_input = f"{h64}.{p64}".encode()
    sig = sign_principal(principal, signing_input)
    return f"{h64}.{p64}.{sig}"


def parse_jws_unverified(jws: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    h64, p64, _sig = jws.split(".")
    return json.loads(b64url_decode(h64)), json.loads(b64url_decode(p64))


def verify_jws(jws: str) -> Tuple[bool, Dict[str, Any], Dict[str, Any]]:
    h64, p64, sig = jws.split(".")
    header = json.loads(b64url_decode(h64))
    payload = json.loads(b64url_decode(p64))
    principal = header.get("kid", "")
    signing_input = f"{h64}.{p64}".encode()
    return verify_principal(principal, signing_input, sig), header, payload


# ---------------------------------------------------------------------------
# Section 3.4 scope monotonicity
# ---------------------------------------------------------------------------


def scope_subset_violation(
    parent: Dict[str, Any], child: Dict[str, Any], path: str = ""
) -> Optional[Dict[str, Any]]:
    """
    Returns None if child ⊆ parent under Section 3.4 rules; else the offending
    field descriptor.
    """
    set_fields = {"actions", "data", "tools"}
    for field, cval in child.items():
        if field not in parent:
            return {"field": f"{path}{field}", "reason": "field_introduced_in_child"}
        pval = parent[field]
        if field in set_fields:
            if not isinstance(cval, list) or not isinstance(pval, list):
                return {"field": f"{path}{field}", "reason": "type_mismatch"}
            extras = set(cval) - set(pval)
            if extras:
                return {
                    "field": f"{path}{field}",
                    "reason": "expanded",
                    "child_value": list(extras),
                    "parent_authorizes": pval,
                }
        elif field == "rate_limit":
            if not isinstance(cval, dict) or not isinstance(pval, dict):
                return {"field": f"{path}{field}", "reason": "type_mismatch"}
            cmax = cval.get("max", 0)
            pmax = pval.get("max", 0)
            if cmax > pmax:
                return {
                    "field": f"{path}rate_limit.max",
                    "reason": "expanded",
                    "child_value": cmax,
                    "parent_authorizes": pmax,
                }
        elif field == "ttl":
            if cval > pval:
                return {
                    "field": f"{path}ttl",
                    "reason": "expanded",
                    "child_value": cval,
                    "parent_authorizes": pval,
                }
        elif isinstance(cval, dict) and isinstance(pval, dict):
            sub = scope_subset_violation(pval, cval, path=f"{path}{field}.")
            if sub is not None:
                return sub
        else:
            if cval != pval:
                return {
                    "field": f"{path}{field}",
                    "reason": "value_changed",
                    "child_value": cval,
                    "parent_authorizes": pval,
                }
    return None


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class IntentObject(BaseModel):
    """Section 3.2 intent_object schema."""

    action: str
    scope: Dict[str, Any]
    target: Optional[str] = None
    constraints: Optional[Dict[str, Any]] = None


class SignIntentRequest(BaseModel):
    originator: str
    intent_object: IntentObject
    authorized_chain: List[str] = Field(default_factory=list)
    ttl_seconds: int = 600


class DelegationLayerRequest(BaseModel):
    delegator: str
    delegatee: str
    scope_reduction: Dict[str, Any]
    inner_jws: str
    ttl_seconds: int = 300


class IssueIntentScopedTokenRequest(BaseModel):
    chain_jws: str
    scope: Dict[str, Any]


class GateOperationRequest(BaseModel):
    token: Dict[str, Any]
    operation: Dict[str, Any]


class BehavioralClaimsRequest(BaseModel):
    subject: str
    issuer: str
    claims: Dict[str, Any]
    evidence: Optional[Dict[str, Any]] = None
    ttl_seconds: int = 7 * 86400


# ---------------------------------------------------------------------------
# Originator: sign root intent (used by both tracks)
# ---------------------------------------------------------------------------


def build_signed_intent(req: SignIntentRequest) -> Dict[str, Any]:
    if req.originator not in _principal_keys:
        raise ValueError("unknown principal")
    intent_canonical = jcs_canonical(req.intent_object.dict(exclude_none=True))
    intent_hash = sha256_b64url(intent_canonical)
    payload = {
        "del_chain_ver": "0.1",
        "intent_root": True,
        "originator": req.originator,
        "intent_object": req.intent_object.dict(exclude_none=True),
        "intent_hash": intent_hash,
        "authorized_chain": req.authorized_chain,
        "scope": req.intent_object.scope,
        "iat": now(),
        "exp": now() + req.ttl_seconds,
        "jti": f"intent_{secrets.token_hex(8)}",
    }
    jws = compact_jws(req.originator, payload)
    return {"intent_jws": jws, "intent_hash": intent_hash, "payload": payload}


def wrap_delegation(req: DelegationLayerRequest) -> Dict[str, Any]:
    """Wrap a delegation layer. Does NOT enforce monotonicity at signing time
    in the broken track; the solution track verifies on receipt."""
    if req.delegator not in _principal_keys:
        raise ValueError("unknown delegator")
    payload = {
        "del_chain_ver": "0.1",
        "delegator": req.delegator,
        "delegatee": req.delegatee,
        "scope_reduction": req.scope_reduction,
        "iat": now(),
        "exp": now() + req.ttl_seconds,
        "inner": req.inner_jws,
    }
    return {"chain_jws": compact_jws(req.delegator, payload)}
