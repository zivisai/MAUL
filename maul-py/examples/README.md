# MAUL Examples — Agent Trust Protocols

This directory contains paired **broken** and **solution** implementations of
the Agent Trust Protocols, organised so a learner can:

1. Hit the broken endpoint and watch an attack succeed.
2. Replay the same artifact against the solution endpoint and watch it fail
   with the structured reason code the spec calls for.
3. Run a single `/scenarios/...` endpoint that does both sides of the demo
   and returns them next to each other for teaching.

Unlike `vulnerabilities/`, this directory is **not exploit-only** — half of
the code here is a spec-conformant verifier. The structure is:

```
examples/
├── ztnp/
│   ├── _common.py     # shared protocol mechanics (signing, JCS, IKS, models)
│   ├── broken.py      # vulnerable endpoints  → /api/examples/ztnp/broken/*
│   ├── solution.py    # spec-conformant       → /api/examples/ztnp/solution/*
│   └── scenarios.py   # end-to-end demos      → /api/examples/ztnp/scenarios/*
└── ztip/
    ├── _common.py
    ├── broken.py      # → /api/examples/ztip/broken/*
    ├── solution.py    # → /api/examples/ztip/solution/*
    └── scenarios.py   # → /api/examples/ztip/scenarios/*
```

Both tracks share `_common.py` for protocol mechanics that are not security
decisions (signing keys, JCS canonicalization, JWS construction, models, the
in-memory IKS / principal registry). Security decisions — what to verify,
which scope checks to run, what to reject — live exclusively in `solution.py`.

The broken and solution tracks share the same in-memory state, so an
artifact minted by `/api/examples/ztnp/broken/enroll` can be replayed
straight against `/api/examples/ztnp/solution/verify-pa`.

## Quick tour

```bash
# 1. Watch ZTIP catch the prompt-injected confused deputy
curl -X POST http://localhost:8000/api/examples/ztip/scenarios/confused-deputy

# 2. Watch ZTNP catch a stolen-PA replay
curl -X POST http://localhost:8000/api/examples/ztnp/scenarios/replay

# 3. List all scenarios for each protocol
curl http://localhost:8000/api/examples/ztnp/scenarios
curl http://localhost:8000/api/examples/ztip/scenarios
```

Each scenario response includes a `lesson` field citing the relevant draft
section.

## References

- ZTNP: <https://github.com/agent-trust-protocols/agent-trust-protocols/blob/main/drafts/ztnp/draft-miller-ztnp-00.md>
- ZTIP: <https://github.com/agent-trust-protocols/agent-trust-protocols/blob/main/drafts/ztip/draft-miller-ztip-00.md>
