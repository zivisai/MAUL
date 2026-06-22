# ATP Lab — multi-container ZTNP / ZTIP demonstration

This directory is a separate `docker-compose` project that spins up a real
multi-agent topology to demonstrate the Agent Trust Protocols end-to-end:

- **5 long-running agent services** — `issuer`, `originator`, `orchestrator`,
  `worker`, `tool` — each in its own container, each with its own Ed25519
  keypair.
- **Mutual TLS between every pair**, signed by a self-signed CA the
  `certs` init container mints at first start.
- **RFC 5929 `tls-server-end-point` channel binding** — the closest channel
  binding mechanism Python's `ssl` module exposes without dropping to
  OpenSSL bindings. Production deployments should use RFC 9266
  `tls-exporter`; the protocol logic is identical.
- **Cross-container Posture Assertion enrollment** — the worker enrolls
  with the issuer over mTLS at runtime, binding the PA to the tool's
  challenge nonce.
- **A driver container** that walks each scenario end-to-end and prints
  broken-track vs solution-track outcomes side by side.

This is independent of the main MAUL `docker-compose.yml`.

## Topology

```
        ┌────────────┐                ┌─────────────┐
        │ originator │                │   issuer    │
        │  (Alice)   │                │ (publishes  │
        │            │                │     IKS)    │
        └─────┬──────┘                └──────┬──────┘
              │ POST /sign-intent             │ POST /enroll/strict
              ▼                                ▼ (worker enrolls; PA bound to challenge nonce)
        ┌────────────┐    POST /delegate    ┌────────────┐
        │orchestrator├─────────────────────▶│   worker   │
        │            │                       │ (act-honest│
        │            │                       │  / injected)│
        └────────────┘                       └─────┬──────┘
                                                   │ POST /broken/operation
                                                   │ POST /solution/operation
                                                   ▼
                                            ┌────────────┐
                                            │    tool    │
                                            │  (verifier)│
                                            └────────────┘
```

Every arrow is a mutual-TLS HTTPS call.

## Quick start

```bash
# 1. Build images and start the long-running services
docker compose -f lab/docker-compose.yml up --build -d

# 2. Run the driver - prints broken vs solution outcomes for each scenario
docker compose -f lab/docker-compose.yml --profile driver run --rm driver

# 3. Tail the tool's logs while the driver is running (in another terminal)
docker compose -f lab/docker-compose.yml logs -f tool

# 4. Tear down
docker compose -f lab/docker-compose.yml down -v
```

## What the driver demonstrates

| Scenario | Broken outcome | Solution outcome |
|----------|----------------|-------------------|
| Prompt-injected confused deputy (ZTIP §4) | `email.send` ALLOWed | `INTENT_SCOPE_MISMATCH` (action) |
| Scope expansion mid-chain (ZTIP §3.4) | expanded chain ALLOWed | `DEL_CHAIN_SCOPE_EXPANDED` |
| Self-attested tier-5 PA (ZTNP §11) | tier accepted at face value | `ENROLLMENT_MODE_INSUFFICIENT` + `POLICY_METHOD_MISMATCH` |

The driver also issues an honest call after each adversarial one to prove
the solution track does not over-block legitimate traffic.

## Per-service endpoints

Each agent listens on `https://<name>:8443`.

- `issuer`
  - `GET /iks` — Issuer Key Set
  - `POST /enroll/strict` — issue assessed/human_review PA
  - `POST /enroll/loose` — issue self/self_attestation PA
- `originator`
  - `POST /sign-intent` — sign root Intent (ZTIP §3.2)
- `orchestrator`
  - `POST /delegate-honest` — wrap a delegation layer
  - `POST /delegate-broken` — wrap a layer with arbitrary scope (still
    receiver-rejected at the solution tool gate)
- `worker`
  - `POST /act-honest` — perform the operation as instructed
  - `POST /act-injected` — simulate prompt injection
- `tool`
  - `POST /challenge` — issue ZTNP challenge nonce
  - `POST /broken/operation` — no checks
  - `POST /solution/operation` — full ZTNP + ZTIP enforcement

All services expose `GET /.well-known/atp-pubkey` for cross-service key
discovery and `GET /health` for readiness checks.

## Files

```
lab/
├── docker-compose.yml          # 6-service topology (5 agents + driver)
├── README.md                   # this file
├── setup/
│   ├── Dockerfile              # alpine + openssl
│   └── generate-certs.sh       # mints CA + 6 service certs into a volume
├── agent/                      # one image, picks service via SERVICE_NAME
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py                 # entrypoint
│   ├── shared/
│   │   ├── atp.py              # protocol primitives (chain verify, PA verify, monotonicity)
│   │   ├── tls.py              # mTLS + cert-fingerprint helpers
│   │   └── peer.py             # mTLS httpx client + key directory cache
│   └── services/
│       ├── issuer.py
│       ├── originator.py
│       ├── orchestrator.py
│       ├── worker.py
│       └── tool.py
└── driver/
    ├── Dockerfile
    └── run.py                  # walks scenarios, prints side-by-side results
```

## Caveats

- `tls-server-end-point` (RFC 5929) binds to the server certificate's
  SHA-256, not the live exporter material RFC 9266 specifies. For
  production-grade channel binding, use a TLS library that exposes the
  exporter (e.g. via the `cryptography` hazmat layer).
- The lab's JCS implementation is a `sort_keys=True, separators=(',',':')`
  approximation. Production must use a conformant RFC 8785 library.
- Issuer + originator key custody is a process-boundary trust model in
  this lab. Real deployments use HSMs or KMS-managed keys.

## References

- ZTNP: <https://github.com/agent-trust-protocols/agent-trust-protocols/blob/main/drafts/ztnp/draft-miller-ztnp-00.md>
- ZTIP: <https://github.com/agent-trust-protocols/agent-trust-protocols/blob/main/drafts/ztip/draft-miller-ztip-00.md>
