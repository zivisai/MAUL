"""
mTLS server config + RFC 5929 tls-server-end-point channel binding helper.

Each lab service runs uvicorn with mTLS:
  - Server cert from /certs/<name>.crt + /certs/<name>.key
  - Client certs verified against /certs/ca.crt
  - cert_reqs = CERT_REQUIRED so unauthenticated callers are rejected at TLS

Channel binding context per service is the SHA-256 of the server's DER cert
(RFC 5929 tls-server-end-point). It is computed once at startup and used
both at PA issuance time (binding the PA to the channel it was negotiated
on) and at Permit validation time. This is not RFC 9266 tls-exporter
(which would require OpenSSL exporter bindings not exposed by Python's
ssl module), but it IS a real cryptographic binding to the TLS channel.
"""

import hashlib
import os
import ssl
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding


CERTS_DIR = os.environ.get("CERTS_DIR", "/certs")


def _cert_path(name: str) -> str:
    return os.path.join(CERTS_DIR, f"{name}.crt")


def _key_path(name: str) -> str:
    return os.path.join(CERTS_DIR, f"{name}.key")


def ca_path() -> str:
    return os.path.join(CERTS_DIR, "ca.crt")


def server_uvicorn_kwargs(service_name: str, port: int = 8443) -> dict:
    """Args for uvicorn.run(..., **server_uvicorn_kwargs(...)) to enforce mTLS."""
    return {
        "host": "0.0.0.0",
        "port": port,
        "ssl_keyfile": _key_path(service_name),
        "ssl_certfile": _cert_path(service_name),
        "ssl_ca_certs": ca_path(),
        "ssl_cert_reqs": ssl.CERT_REQUIRED,
    }


def cert_fingerprint_b64url(service_name: str) -> str:
    """
    SHA-256 fingerprint of the service's DER-encoded cert, base64url'd.
    This IS the RFC 5929 tls-server-end-point channel binding context for
    this server's TLS endpoint.
    """
    with open(_cert_path(service_name), "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    der = cert.public_bytes(Encoding.DER)
    digest = hashlib.sha256(der).digest()
    import base64

    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def cert_fingerprint_for_peer(peer_pem_path: str) -> str:
    """Compute another service's cert fingerprint from its public PEM file
    (each cert is mounted into every container under /certs/)."""
    with open(peer_pem_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    der = cert.public_bytes(Encoding.DER)
    digest = hashlib.sha256(der).digest()
    import base64

    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def peer_cert_path(name: str) -> str:
    return _cert_path(name)
