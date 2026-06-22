"""
Lab driver - walks each scenario end-to-end across the running containers,
prints the broken-track outcome and then the solution-track outcome
side-by-side. mTLS-enabled httpx client throughout.

Run inside the lab compose project after the agent services are up:

    docker compose -f lab/docker-compose.yml run --rm driver
"""

import os
import ssl
import sys
import time
from typing import Any, Dict

import httpx


CERTS_DIR = os.environ.get("CERTS_DIR", "/certs")
CA = f"{CERTS_DIR}/ca.crt"
CLIENT_CERT = f"{CERTS_DIR}/driver.crt"
CLIENT_KEY = f"{CERTS_DIR}/driver.key"
PORT = 8443


def url(host: str, path: str) -> str:
    return f"https://{host}:{PORT}{path}"


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=CA)
    ctx.load_cert_chain(CLIENT_CERT, CLIENT_KEY)
    return ctx


def client(timeout: float = 15.0) -> httpx.Client:
    return httpx.Client(verify=_ssl_context(), timeout=timeout)


# ---------------------------------------------------------------------------
# Wait for services
# ---------------------------------------------------------------------------


def wait_for_service(c: httpx.Client, host: str, max_seconds: int = 60) -> None:
    deadline = time.time() + max_seconds
    last_err: Exception | None = None
    while time.time() < deadline:
        try:
            r = c.get(url(host, "/health"))
            if r.status_code == 200:
                return
        except Exception as e:
            last_err = e
        time.sleep(1)
    raise RuntimeError(f"{host} did not become healthy within {max_seconds}s: {last_err}")


# ---------------------------------------------------------------------------
# Pretty printing
# ---------------------------------------------------------------------------


def banner(title: str) -> None:
    print()
    print("=" * 72)
    print(f"  {title}")
    print("=" * 72)


def show(label: str, payload: Any) -> None:
    print(f"\n--- {label} ---")
    if isinstance(payload, dict):
        for k, v in payload.items():
            if isinstance(v, dict):
                print(f"  {k}:")
                for kk, vv in v.items():
                    print(f"    {kk}: {vv}")
            else:
                print(f"  {k}: {v}")
    else:
        print(f"  {payload}")


# ---------------------------------------------------------------------------
# Scenario flow
# ---------------------------------------------------------------------------


# The honest user intent. Read-only summarization of internal email.
USER_INTENT = {
    "action": "summarize",
    "scope": {
        "actions": ["read"],
        "tools": ["email.read", "email.list"],
        "data": ["internal"],
    },
    "target": "unread emails today",
    "constraints": {"must_not": ["email.send", "email.delete"]},
}

LEGITIMATE_OP = {"action": "read", "tool": "email.read", "data": ["internal"]}
INJECTED_OP = {"action": "send", "tool": "email.send", "data": ["pii"]}


def build_chain(c: httpx.Client) -> str:
    """Originator signs intent. Orchestrator wraps a delegation layer.
    Returns the chain JWS at orchestrator level (worker will wrap its own
    layer when it makes the tool call)."""
    intent = c.post(
        url("originator", "/sign-intent"),
        json={
            "intent_object": USER_INTENT,
            "authorized_chain": ["orchestrator", "worker"],
        },
    ).json()

    chain = c.post(
        url("orchestrator", "/delegate-honest"),
        json={
            "inner_jws": intent["intent_jws"],
            "delegatee": "worker",
            "scope_reduction": {
                "actions": ["read"],
                "tools": ["email.read"],
                "data": ["internal"],
            },
        },
    ).json()
    return chain["chain_jws"]


def build_chain_with_expansion(c: httpx.Client) -> str:
    """Orchestrator signs an EXPANDED scope (read + send) - this is the
    mid-chain compromise scenario."""
    intent = c.post(
        url("originator", "/sign-intent"),
        json={
            "intent_object": USER_INTENT,
            "authorized_chain": ["orchestrator", "worker"],
        },
    ).json()
    chain = c.post(
        url("orchestrator", "/delegate-broken"),
        json={
            "inner_jws": intent["intent_jws"],
            "delegatee": "worker",
            "scope_reduction": {
                "actions": ["read", "send"],  # EXPANDED
                "tools": ["email.read", "email.send"],
                "data": ["internal"],
            },
        },
    ).json()
    return chain["chain_jws"]


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------


def scenario_confused_deputy(c: httpx.Client) -> None:
    banner("Scenario 1: Prompt-injected confused deputy (ZTIP Section 4)")
    chain = build_chain(c)

    print("\n[broken track] worker is prompt-injected and calls email.send")
    broken = c.post(
        url("worker", "/act-injected"),
        json={
            "chain_jws": chain,
            "operation": LEGITIMATE_OP,
            "tool_endpoint": "/broken/operation",
        },
    ).json()
    show("broken /act-injected response", broken)

    print("\n[solution track] same injected operation, solution endpoint")
    solution = c.post(
        url("worker", "/act-injected"),
        json={
            "chain_jws": chain,
            "operation": LEGITIMATE_OP,
            "tool_endpoint": "/solution/operation",
        },
    ).json()
    show("solution /act-injected response", solution)

    print("\n[solution track] HONEST call (no injection) - should ALLOW")
    honest = c.post(
        url("worker", "/act-honest"),
        json={
            "chain_jws": chain,
            "operation": LEGITIMATE_OP,
            "tool_endpoint": "/solution/operation",
        },
    ).json()
    show("solution /act-honest response", honest)


def scenario_scope_expansion(c: httpx.Client) -> None:
    banner("Scenario 2: Scope expansion mid-chain (ZTIP Section 3.4)")
    chain = build_chain_with_expansion(c)

    print("\n[broken track] expanded chain accepted, send goes through")
    broken = c.post(
        url("worker", "/act-honest"),
        json={
            "chain_jws": chain,
            "operation": INJECTED_OP,  # send, which expanded chain claims to permit
            "tool_endpoint": "/broken/operation",
        },
    ).json()
    show("broken /act-honest response", broken)

    print("\n[solution track] DEL_CHAIN_SCOPE_EXPANDED")
    solution = c.post(
        url("worker", "/act-honest"),
        json={
            "chain_jws": chain,
            "operation": INJECTED_OP,
            "tool_endpoint": "/solution/operation",
        },
    ).json()
    show("solution /act-honest response", solution)


def scenario_self_attest(c: httpx.Client) -> None:
    """Direct PA test - bypass the worker and present a self-attested PA
    straight to the tool."""
    banner("Scenario 3: Self-attested tier-5 PA (ZTNP Section 11)")

    # Get a fresh challenge from the tool.
    ch = c.post(url("tool", "/challenge"), json={"sub": "worker"}).json()

    # Mint a self/self_attestation tier-5 PA from the loose enrollment endpoint.
    pa = c.post(
        url("issuer", "/enroll/loose"),
        json={
            "sub": "worker",
            "framework_id": "https://genai.owasp.org/llm-top-10/2025",
            "tier": 5,
            "bind_nonce": ch["challenge_nonce"],
        },
    ).json()

    # Build a minimal honest chain to satisfy ZTIP separately.
    chain_at_orch = build_chain(c)
    chain = c.post(
        url("orchestrator", "/delegate-honest"),
        json={
            "inner_jws": chain_at_orch,
            "delegatee": "worker",
            "scope_reduction": {
                "actions": ["read"],
                "tools": ["email.read"],
                "data": ["internal"],
            },
        },
    ).json()["chain_jws"]

    print("\n[solution track] tool checks PA against framework + tier policy")
    resp = c.post(
        url("tool", "/solution/operation"),
        json={
            "challenge_id": ch["challenge_id"],
            "pa": pa,
            "chain_jws": chain,
            "intent_scoped_token": {
                "intent_hash": "ignored-in-this-scenario",
                "intent_scope": {},
                "chain_root_iss": "originator",
                "chain_root_jti": "x",
            },
            "operation": LEGITIMATE_OP,
        },
    ).json()
    show("solution /operation response (self-attested PA)", resp)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    print(f"[driver] CA at {CA}")
    print(f"[driver] client cert {CLIENT_CERT[0]}")

    c = client()
    print("[driver] waiting for services to come up...")
    for host in ("issuer", "originator", "orchestrator", "worker", "tool"):
        wait_for_service(c, host)
        print(f"  {host}: ready")

    scenario_confused_deputy(c)
    scenario_scope_expansion(c)
    scenario_self_attest(c)

    print()
    print("=" * 72)
    print("  Lab driver done.")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
