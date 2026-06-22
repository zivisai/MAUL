"""
Agent Trust Protocols - reference primitives used by every lab service.

This is the cross-container shared library. It contains protocol mechanics
(JCS, JWS, signing, monotonicity check, full chain + PA verifiers). It does
NOT contain any lab-wide registry: each service holds its own keypair and
discovers others by HTTPS calls to their well-known endpoints.

Reference: draft-miller-ztnp-00, draft-miller-ztip-00.
"""

import json
import time
import base64
import hashlib
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def jcs_canonical(obj: Any) -> bytes:
    """Simplified JCS-style canonicalization (RFC 8785). Sufficient for the
    payloads the lab uses; production requires a conformant JCS lib."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_b64url(data: bytes) -> str:
    return b64url(hashlib.sha256(data).digest())


def now() -> int:
    return int(time.time())


# ---------------------------------------------------------------------------
# Ed25519 key management - per-service
# ---------------------------------------------------------------------------


class KeyPair:
    """An Ed25519 keypair owned by a single principal (one container).
    Keys are generated at startup and persist for the container's lifetime.
    Public key is published at the service's /.well-known/atp-pubkey endpoint."""

    def __init__(self, principal_id: str):
        self.principal_id = principal_id
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key()

    @property
    def public_b64url(self) -> str:
        return b64url(
            self.public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )

    def sign(self, payload: bytes) -> bytes:
        return self.private.sign(payload)


def public_key_from_b64url(b64: str) -> Ed25519PublicKey:
    raw = b64url_decode(b64)
    return Ed25519PublicKey.from_public_bytes(raw)


# ---------------------------------------------------------------------------
# Compact JWS over Ed25519
# ---------------------------------------------------------------------------


def compact_jws(key: KeyPair, payload: Dict[str, Any]) -> str:
    header = {"alg": "EdDSA", "kid": key.principal_id}
    h64 = b64url(jcs_canonical(header))
    p64 = b64url(jcs_canonical(payload))
    signing_input = f"{h64}.{p64}".encode()
    sig = b64url(key.sign(signing_input))
    return f"{h64}.{p64}.{sig}"


def parse_jws_unverified(jws: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    h64, p64, _sig = jws.split(".")
    return json.loads(b64url_decode(h64)), json.loads(b64url_decode(p64))


def verify_jws(
    jws: str, public_key_resolver
) -> Tuple[bool, Dict[str, Any], Dict[str, Any]]:
    """
    public_key_resolver(kid: str) -> Ed25519PublicKey | None
    """
    h64, p64, sig_b64 = jws.split(".")
    header = json.loads(b64url_decode(h64))
    payload = json.loads(b64url_decode(p64))
    pk = public_key_resolver(header.get("kid", ""))
    if pk is None:
        return False, header, payload
    try:
        pk.verify(b64url_decode(sig_b64), f"{h64}.{p64}".encode())
        return True, header, payload
    except Exception:
        return False, header, payload


# ---------------------------------------------------------------------------
# Section 3.4 scope monotonicity
# ---------------------------------------------------------------------------


def scope_subset_violation(
    parent: Dict[str, Any], child: Dict[str, Any], path: str = ""
) -> Optional[Dict[str, Any]]:
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
            if cval.get("max", 0) > pval.get("max", 0):
                return {
                    "field": f"{path}rate_limit.max",
                    "reason": "expanded",
                    "child_value": cval.get("max"),
                    "parent_authorizes": pval.get("max"),
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
# ZTIP - chain construction
# ---------------------------------------------------------------------------


def build_root_intent(
    key: KeyPair,
    intent_object: Dict[str, Any],
    authorized_chain: List[str],
    ttl_seconds: int = 600,
) -> Dict[str, Any]:
    intent_hash = sha256_b64url(jcs_canonical(intent_object))
    payload = {
        "del_chain_ver": "0.1",
        "intent_root": True,
        "originator": key.principal_id,
        "intent_object": intent_object,
        "intent_hash": intent_hash,
        "authorized_chain": authorized_chain,
        "scope": intent_object.get("scope", {}),
        "iat": now(),
        "exp": now() + ttl_seconds,
        "jti": f"intent_{b64url(hashlib.sha256(jcs_canonical(intent_object)).digest()[:8])}",
    }
    return {
        "intent_jws": compact_jws(key, payload),
        "intent_hash": intent_hash,
        "payload": payload,
    }


def wrap_delegation(
    key: KeyPair,
    delegatee: str,
    scope_reduction: Dict[str, Any],
    inner_jws: str,
    ttl_seconds: int = 300,
) -> str:
    payload = {
        "del_chain_ver": "0.1",
        "delegator": key.principal_id,
        "delegatee": delegatee,
        "scope_reduction": scope_reduction,
        "iat": now(),
        "exp": now() + ttl_seconds,
        "inner": inner_jws,
    }
    return compact_jws(key, payload)


# ---------------------------------------------------------------------------
# ZTIP - chain verification (Section 3.3)
# ---------------------------------------------------------------------------


def verify_chain(
    jws: str,
    public_key_resolver,
    trusted_originators: List[str],
    max_depth: int = 8,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Returns (layers_outermost_first, reason_codes). Empty reasons -> valid.
    Implements Section 3.3 rules 1-7 and Section 3.4 monotonicity.
    """
    # Rule 6: depth check before any signature work
    depth = 0
    probe = jws
    while True:
        depth += 1
        if depth > max_depth:
            return [], ["DEL_CHAIN_DEPTH_EXCEEDED"]
        try:
            _h, p = parse_jws_unverified(probe)
        except Exception:
            return [], ["DEL_CHAIN_BROKEN"]
        if p.get("intent_root"):
            break
        probe = p.get("inner")
        if not probe:
            return [], ["DEL_CHAIN_BROKEN"]

    # Rules 1 + 5: verify each layer, freshness
    layers: List[Dict[str, Any]] = []
    cur = jws
    while True:
        try:
            ok, _h, payload = verify_jws(cur, public_key_resolver)
        except Exception:
            return [], ["DEL_CHAIN_BROKEN"]
        if not ok:
            return [], ["DEL_CHAIN_BAD_SIGNATURE"]
        if payload.get("exp", 0) < now() - 5:
            return [], ["DEL_CHAIN_EXPIRED"]
        layers.append(payload)
        if payload.get("intent_root"):
            break
        cur = payload.get("inner")
        if not cur:
            return [], ["DEL_CHAIN_BROKEN"]

    root = layers[-1]

    # Rule 4: trusted Originator
    if root.get("originator") not in trusted_originators:
        return [], ["DEL_CHAIN_UNTRUSTED_ROOT"]

    # Rule 7: intent_hash recomputation
    if sha256_b64url(jcs_canonical(root.get("intent_object") or {})) != root.get(
        "intent_hash"
    ):
        return [], ["INTENT_HASH_MISMATCH_ROOT"]

    # Rules 2 + 3: walk root -> outermost
    parent_scope = root.get("scope", {})
    parent_principal = root.get("originator")
    authorized = root.get("authorized_chain", [])
    for layer in reversed(layers[:-1]):
        if layer.get("delegator") != parent_principal and layer.get(
            "delegator"
        ) not in authorized:
            return [], ["DEL_CHAIN_BROKEN"]
        violation = scope_subset_violation(
            parent_scope, layer.get("scope_reduction", {})
        )
        if violation is not None:
            return [], ["DEL_CHAIN_SCOPE_EXPANDED", json.dumps(violation)]
        parent_scope = layer.get("scope_reduction", {})
        parent_principal = layer.get("delegatee")

    return layers, []


def gate_operation_with_chain(
    op: Dict[str, Any],
    chain_jws: str,
    intent_hash_claim: str,
    public_key_resolver,
    trusted_originators: List[str],
) -> Dict[str, Any]:
    """Section 4.2 spec-conformant gate: verify chain, recompute intent_hash,
    enforce intent_scope subset of operation."""
    layers, reasons = verify_chain(
        chain_jws, public_key_resolver, trusted_originators
    )
    if reasons:
        return {"decision": "DENY", "reason": "INTENT_SCOPE_MISMATCH", "details": reasons}
    root = layers[-1]
    recomputed = sha256_b64url(jcs_canonical(root.get("intent_object") or {}))
    if recomputed != intent_hash_claim:
        return {"decision": "DENY", "reason": "INTENT_HASH_MISMATCH"}
    intent_scope = root.get("scope") or {}
    if "actions" in intent_scope and op.get("action") not in intent_scope["actions"]:
        return {
            "decision": "DENY",
            "reason": "INTENT_SCOPE_MISMATCH",
            "field": "action",
            "value": op.get("action"),
        }
    if "tools" in intent_scope and op.get("tool") not in intent_scope["tools"]:
        return {
            "decision": "DENY",
            "reason": "INTENT_SCOPE_MISMATCH",
            "field": "tool",
            "value": op.get("tool"),
        }
    if "data" in intent_scope:
        for d in op.get("data", []):
            if d not in intent_scope["data"]:
                return {
                    "decision": "DENY",
                    "reason": "INTENT_SCOPE_MISMATCH",
                    "field": "data",
                    "value": d,
                }
    return {"decision": "ALLOW", "intent_scope": intent_scope}


# ---------------------------------------------------------------------------
# ZTNP - PA construction + verification
# ---------------------------------------------------------------------------


def build_signed_pa(
    issuer_key: KeyPair,
    sub: str,
    framework_id: str,
    tier: int,
    enrollment_mode: str,
    assessment_method: str,
    bind_nonce: Optional[str] = None,
    ttl_seconds: int = 3600,
    flags: Optional[Dict[str, bool]] = None,
) -> Dict[str, Any]:
    pa: Dict[str, Any] = {
        "ver": "0.2",
        "iss": issuer_key.principal_id,
        "sub": sub,
        "iat": now(),
        "exp": now() + ttl_seconds,
        "jti": "pa_" + b64url(
            hashlib.sha256(f"{sub}|{now()}".encode()).digest()[:8]
        ),
        "framework_id": framework_id,
        "tier": tier,
        "scope": {"kind": "agent", "target": sub},
        "claims": {
            "flags": flags or {},
            "posture": {},
            "assessment_method": assessment_method,
        },
        "enrollment_mode": enrollment_mode,
    }
    if bind_nonce:
        pa["bind"] = {
            "method": "nonce_hash",
            "nonce": sha256_b64url(bind_nonce.encode()),
        }
    payload_for_sig = jcs_canonical(pa)
    pa["sig"] = b64url(issuer_key.sign(payload_for_sig))
    return pa


def verify_pa(
    pa: Dict[str, Any],
    issuer_pubkey_resolver,
    challenge_nonce: Optional[str],
    policy: Dict[str, Any],
) -> List[str]:
    """Returns reasons; empty -> valid. Section 5 verification rules."""
    reasons: List[str] = []
    sig = pa.get("sig")
    if not sig:
        return ["PA_UNSIGNED"]
    payload = {k: v for k, v in pa.items() if k != "sig"}
    pk = issuer_pubkey_resolver(pa.get("iss", ""))
    if pk is None:
        return ["ISSUER_UNKNOWN"]
    try:
        pk.verify(b64url_decode(sig), jcs_canonical(payload))
    except Exception:
        return ["PA_BAD_SIGNATURE"]

    if pa.get("exp", 0) < now() - 5:
        reasons.append("PA_EXPIRED")
    if pa.get("iat", 0) > now() + 300:
        reasons.append("PA_IAT_FUTURE")
    if now() - pa.get("iat", 0) > policy.get("max_pa_age_seconds", 3600):
        reasons.append("PA_STALE")

    if challenge_nonce is not None:
        bind = pa.get("bind") or {}
        if bind.get("method") != "nonce_hash":
            reasons.append("PA_BIND_METHOD_UNSUPPORTED")
        else:
            expected = sha256_b64url(challenge_nonce.encode())
            if bind.get("nonce") != expected:
                reasons.append("PA_BIND_MISMATCH")

    if pa.get("iss") not in policy.get("issuers_allowed", []):
        reasons.append("ISSUER_UNTRUSTED")

    fid = pa.get("framework_id", "")
    if fid not in policy.get("frameworks_allowed", []):
        reasons.append("FRAMEWORK_UNRECOGNIZED")
    else:
        tier_min = policy.get("tier_min_by_framework", {}).get(fid, 99)
        if pa.get("tier", 0) < tier_min:
            reasons.append("TIER_TOO_LOW")

    method = (pa.get("claims") or {}).get("assessment_method")
    if method not in policy.get("assessment_method_allowed", []):
        reasons.append("POLICY_METHOD_MISMATCH")

    if (
        pa.get("enrollment_mode") == "self"
        and policy.get("enrollment_mode_min") == "assessed"
        and pa.get("tier", 0) > 1
    ):
        reasons.append("ENROLLMENT_MODE_INSUFFICIENT")

    return reasons
