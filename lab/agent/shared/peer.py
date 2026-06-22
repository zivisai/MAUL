"""
mTLS-enabled httpx client + lightweight cross-container key directory.

Each service exposes its public Ed25519 key at /.well-known/atp-pubkey. This
module:

  - Issues all cross-service HTTP calls under mTLS using the caller's own
    cert (so the receiving server can verify the caller).
  - Caches discovered public keys per principal id (`kid`) so chain layer
    signature verification can resolve keys without repeated round-trips.
"""

import os
import ssl
from typing import Dict, Optional

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .atp import public_key_from_b64url
from .tls import _cert_path, _key_path, ca_path


_PRINCIPAL_TO_HOST: Dict[str, str] = {
    "issuer": "issuer",
    "originator": "originator",
    "orchestrator": "orchestrator",
    "worker": "worker",
    "tool": "tool",
}

_PORT = 8443


def _build_ssl_context(self_service_name: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=ca_path())
    ctx.load_cert_chain(_cert_path(self_service_name), _key_path(self_service_name))
    return ctx


def make_client(self_service_name: str, timeout: float = 10.0) -> httpx.Client:
    """httpx.Client with mTLS configured for this service's identity. Uses an
    explicit SSLContext so the client cert + CA are loaded the same way across
    httpx versions (0.28+ removed the top-level `cert=` argument)."""
    return httpx.Client(
        verify=_build_ssl_context(self_service_name),
        timeout=timeout,
    )


def url(host: str, path: str) -> str:
    return f"https://{host}:{_PORT}{path}"


# ---------------------------------------------------------------------------
# Cross-container key directory
# ---------------------------------------------------------------------------


_KEY_CACHE: Dict[str, Ed25519PublicKey] = {}


def fetch_pubkey(client: httpx.Client, kid: str) -> Optional[Ed25519PublicKey]:
    """Resolve a principal id (kid) to its published Ed25519 public key.
    The kid IS the service name in the lab (e.g. "originator")."""
    if kid in _KEY_CACHE:
        return _KEY_CACHE[kid]
    host = _PRINCIPAL_TO_HOST.get(kid)
    if host is None:
        return None
    try:
        resp = client.get(url(host, "/.well-known/atp-pubkey"))
        resp.raise_for_status()
        data = resp.json()
        pk = public_key_from_b64url(data["public_key"])
        _KEY_CACHE[kid] = pk
        return pk
    except Exception:
        return None


def make_resolver(client: httpx.Client):
    """Returns a public_key_resolver suitable for shared.atp.verify_chain."""

    def resolve(kid: str) -> Optional[Ed25519PublicKey]:
        return fetch_pubkey(client, kid)

    return resolve


def prime_cache(kid: str, pk: Ed25519PublicKey) -> None:
    """Allow a service to seed its own key into the cache (avoids self-call)."""
    _KEY_CACHE[kid] = pk


def prefetch_peers(
    self_service_name: str,
    peers: list[str],
    max_seconds: int = 60,
    sleep_seconds: float = 0.5,
) -> None:
    """
    Block until every named peer's /.well-known/atp-pubkey has been fetched
    and cached. Used at startup by the tool so the resolver never needs to
    call back to peers (which can deadlock if a peer is mid-call to us).
    """
    import time

    client = make_client(self_service_name, timeout=3.0)
    deadline = time.time() + max_seconds
    pending = list(peers)
    while pending and time.time() < deadline:
        still: list[str] = []
        for kid in pending:
            host = _PRINCIPAL_TO_HOST.get(kid, kid)
            try:
                resp = client.get(url(host, "/.well-known/atp-pubkey"))
                resp.raise_for_status()
                _KEY_CACHE[kid] = public_key_from_b64url(resp.json()["public_key"])
            except Exception:
                still.append(kid)
        if not still:
            return
        time.sleep(sleep_seconds)
        pending = still
    if pending:
        raise RuntimeError(f"prefetch_peers timed out for: {pending}")


def cached_resolver():
    """Returns a resolver that ONLY consults the in-memory cache. Use this on
    the request-handling hot path to avoid synchronous outbound HTTP calls
    that can deadlock under sync httpx in async handlers."""

    def resolve(kid: str) -> Optional[Ed25519PublicKey]:
        return _KEY_CACHE.get(kid)

    return resolve
