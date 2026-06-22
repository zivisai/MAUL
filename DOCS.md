# MAUL - Model & Agent Unsafe Lab

## Complete Project Documentation

**MAUL** is an open-source, deliberately vulnerable AI application designed for penetration testing training, security research, and educational demonstrations of AI-specific vulnerabilities.

---

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Architecture](#architecture)
4. [Vulnerability Categories](#vulnerability-categories)
5. [API Reference](#api-reference)
6. [Database Schema](#database-schema)
7. [Deployment Options](#deployment-options)
8. [Configuration](#configuration)
9. [Development](#development)
10. [Technology Stack](#technology-stack)

---

## Overview

### What is MAUL?

MAUL is a **purpose-built vulnerable AI application** that simulates real-world security flaws found in LLM-powered systems. It provides a safe, legal environment for:

- **Security professionals** learning AI penetration testing
- **Developers** understanding how to avoid AI security pitfalls
- **Red teams** practicing adversarial techniques against LLM applications
- **Educators** demonstrating AI security concepts
- **Anyone** wanting to better understand AI security

### Key Features

| Feature | Description |
|---------|-------------|
| RAG Pipeline | Retrieval-Augmented Generation with intentional vulnerabilities |
| Vector Database | pgvector-powered semantic search with security flaws |
| Multi-Agent System | Multiple agents with exploitable communication |
| Tool-Using Agent | Agent with access to dangerous tools |
| Conversation Persistence | Full chat history stored in PostgreSQL |
| Synthetic PII Dataset | Fake financial profiles for exercises |
| Docker-based | One-command deployment |
| OWASP LLM Top 10 | Comprehensive vulnerability coverage |

### Project Structure

```
maul/
├── docker-compose.yml          # Multi-container orchestration
├── .env.example                # Environment template
├── README.md                   # Project overview
├── CONTRIBUTING.md             # Contribution guidelines
├── LICENSE                     # Apache 2.0
└── maul-py/                    # Main application
    ├── Dockerfile              # Container definition
    ├── requirements.txt        # Python dependencies
    ├── main.py                 # FastAPI application
    ├── db.py                   # Database session management
    ├── langchain_ingest.py     # Vector embedding pipeline
    ├── static/
    │   └── index.html          # Web UI
    ├── vulnerabilities/
    │   ├── __init__.py
    │   ├── agent_tools.py      # Tool-using agent
    │   ├── document_upload.py  # Document/RAG poisoning
    │   ├── streaming.py        # SSE vulnerabilities
    │   ├── embeddings.py       # Embedding attacks
    │   ├── auth.py             # Authentication flaws
    │   ├── output_handling.py  # Output handling issues
    │   ├── multi_agent.py      # Multi-agent system
    │   ├── rbac.py             # Authorization bypass
    │   ├── mcp_servers.py      # MCP protocol vulnerabilities
    │   ├── agent_protocols.py  # A2A protocol vulnerabilities
    │   ├── agent_ecosystem.py  # Multi-agent ecosystem
    │   ├── agent_marketplace.py # Agent registry/marketplace
    │   └── agent_governance.py # Governance bypass
    └── data/
        ├── int_db.py           # Database schema
        └── generate-docs.py    # Synthetic data generator
```

---

## Quick Start

### Prerequisites

- Docker & Docker Compose
- OpenAI API key

### 1. Clone the Repository

```bash
git clone https://github.com/zivisai/MAUL.git
cd MAUL
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env and add your OpenAI API key
```

### 3. Launch the Environment

```bash
docker-compose build
docker-compose up
```

### 4. Access Services

| Service | URL | Purpose |
|---------|-----|---------|
| Web UI | http://localhost:8000 | Interactive interface |
| API Docs | http://localhost:8000/docs | Swagger documentation |
| pgAdmin | http://localhost:8080 | Database administration |
| PostgreSQL | localhost:5432 | Direct database access |

---

## Architecture

### System Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        Docker Network                           │
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │
│  │   Client    │───▶│  FastAPI    │───▶│   OpenAI API        │ │
│  │             │    │  (Port 8000)│    │   (GPT-3.5-turbo)   │ │
│  └─────────────┘    └──────┬──────┘    └─────────────────────┘ │
│                            │                                    │
│                            ▼                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              PostgreSQL + pgvector                       │   │
│  │                   (Port 5432)                            │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │   │
│  │  │conversations│  │  messages   │  │ vector_embeddings│  │   │
│  │  └─────────────┘  └─────────────┘  └─────────────────┘  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐                            │
│  │   pgAdmin   │    │    Redis    │                            │
│  │  (Port 8080)│    │  (Port 6379)│                            │
│  └─────────────┘    └─────────────┘                            │
└─────────────────────────────────────────────────────────────────┘
```

### Request Flow

1. **User sends query** → POST `/api/ask`
2. **Conversation management** → Create/retrieve conversation ID
3. **History retrieval** → Fetch previous messages from PostgreSQL
4. **Vector search** → Query pgvector for similar documents
5. **Context injection** → Prepend retrieved documents to chat history
6. **LLM inference** → Send context to GPT-3.5-turbo
7. **Response persistence** → Store user query and assistant response
8. **Return result** → Send response with conversation ID

---

## Vulnerability Categories

### OWASP LLM Top 10 (2025) Coverage

| # | Category | Module | Endpoints |
|---|----------|--------|-----------|
| LLM01 | Prompt Injection | main.py, multi_agent.py | `/api/ask`, `/api/agents/*` |
| LLM02 | Improper Output Handling | output_handling.py | `/api/output/*` |
| LLM03 | Data and Model Poisoning | document_upload.py | `/api/documents/*` |
| LLM04 | Unbounded Consumption | All | All endpoints |
| LLM06 | Sensitive Information Disclosure | main.py, embeddings.py | `/api/ask`, `/api/embeddings/*` |
| LLM07 | System Prompt Leakage | main.py, multi_agent.py | `/api/ask`, `/api/agents/*` |
| LLM08 | Vector and Embedding Weaknesses | embeddings.py | `/api/embeddings/*` |
| LLM09 | Misinformation | document_upload.py | `/api/documents/*` |
| LLM10 | Excessive Agency | agent_tools.py | `/api/agent/*` |

### Additional Vulnerability Categories

| Category | Module | Description |
|----------|--------|-------------|
| Authentication | auth.py | Session management, credential handling |
| Authorization | rbac.py | Role-based access control |
| Injection | output_handling.py | Command, SQL, code injection |
| Streaming | streaming.py | SSE security issues |
| Multi-Agent | multi_agent.py | Agent trust and communication |
| XSS | output_handling.py | Cross-site scripting |
| SSRF | agent_tools.py, document_upload.py | Server-side request forgery |

### OWASP Agentic AI Threats and Mitigations v1.0 (Feb 2025)

The OWASP GenAI Security Project's [Agentic AI – Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/) defines 15 threats specific to autonomous, tool-using, multi-agent systems. MAUL implements one or more focused, exploitable endpoints for each. The companion module is `vulnerabilities/owasp_agentic.py`.

| ID | Threat | Endpoint | What it shows |
|----|--------|----------|---------------|
| T1 | Memory Poisoning | `POST /api/owasp-agentic/t1/memory/write` | Unauthenticated writes to shared agent memory; downstream `POST /t1/agent/act` trusts the poisoned `user_role` key. |
| T2 | Tool Misuse | `POST /api/owasp-agentic/t2/tool/dispatch` | LLM picks tool + args from free text with no allowlist on recipients/paths/amounts. |
| T3 | Privilege Compromise | `POST /api/owasp-agentic/t3/delegate`, `/t3/escalate` | Delegation grants any requested scope; agents can rewrite their own role. |
| T4 | Resource Overload | `POST /api/owasp-agentic/t4/fanout`, `/t4/loop` | Unbounded fan-out (`branches**depth`) and uncapped re-prompt loops with no per-tenant budget. |
| T5 | Cascading Hallucination | `POST /api/owasp-agentic/t5/cascade` | Each agent in the chain refines the previous claim into something more confident; no re-grounding. |
| T6 | Intent Breaking & Goal Manipulation | `POST /api/owasp-agentic/t6/plan` | Retrieved-context field is concatenated into the system prompt; injected directives override the user goal. |
| T7 | Misaligned & Deceptive Behaviors | `POST /api/owasp-agentic/t7/deceptive-execute` | Agent reports a sanitized public action while a different real action runs; no binding between report and execution. |
| T8 | Repudiation & Untraceability | `GET/POST/DELETE /api/owasp-agentic/t8/log/*` | Audit log is mutable; entries can be edited or deleted. No append-only, no hash chain, no signed entries. |
| T9 | Identity Spoofing | `POST /api/owasp-agentic/t9/agent/send` | `from_agent` and `X-Agent-Id` accepted verbatim — no challenge, signature, or mTLS. |
| T10 | Overwhelming HITL | `POST /api/owasp-agentic/t10/hitl/flood`, `/t10/hitl/auto-approve` | Flood the queue with `count` benign items hiding one malicious request; reviewer auto-approves under fatigue. |
| T11 | Unexpected RCE & Code Attacks | `POST /api/owasp-agentic/t11/code/execute` | Natural-language → shell command via LLM, run with `shell=True`, no sandbox or allowlist. |
| T12 | Agent Communication Poisoning | `POST /api/owasp-agentic/t12/bus/tamper` | Mutate an in-flight inter-agent message body; no signing, MAC, or nonce. |
| T13 | Rogue Agents | `POST /api/owasp-agentic/t13/rogue/register` | Register a malicious agent under a trusted-looking name with self-claimed trust score. |
| T14 | Human Attacks on MAS | `POST /api/owasp-agentic/t14/cross-agent` | Low-privilege entry agent forwards user text into a high-privilege agent's prompt as a "trusted internal message." |
| T15 | Human Manipulation | `POST /api/owasp-agentic/t15/manipulate` | Agent receives a hidden objective and steers the user toward it through a trusted UI. |

Live index of all 15 endpoints: `GET /api/owasp-agentic/catalog`.

### WEF AI Agent Vulnerabilities (2025)

Based on the [World Economic Forum "AI Agents in Action" report](https://www.weforum.org/publications/ai-agents-in-action-foundations-for-evaluation-and-governance-2025/), the following agentic AI-specific vulnerability categories are implemented:

| Category | Module | Description |
|----------|--------|-------------|
| MCP Protocol Exploits | mcp_servers.py | Model Context Protocol server injection, tool boundary violations |
| A2A Protocol Attacks | agent_protocols.py | Agent-to-Agent protocol vulnerabilities, identity spoofing |
| Orchestration Drift | agent_ecosystem.py | Multi-agent coordination failures, semantic misalignment |
| Cascading Failures | agent_ecosystem.py | Systemic risk propagation across agent networks |
| Goal Misalignment | agent_ecosystem.py | Objective drift and reward hacking |
| Memory Poisoning | agent_ecosystem.py | Context manipulation and behavioral drift |
| False Advertisement | agent_marketplace.py | Capability misrepresentation in agent registries |
| Malicious Agent Distribution | agent_marketplace.py | Backdoored agents in marketplace |
| HITL Bypass | agent_governance.py | Human-in-the-loop circumvention |
| Audit Log Tampering | agent_governance.py | Governor/auditor agent bypass |
| Policy Manipulation | agent_governance.py | Runtime policy injection attacks |
| Trust Framework Exploits | agent_protocols.py | Delegation chain attacks, trust escalation |

---

## API Reference

### Core Chat

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/ask` | Main RAG-enabled chat |
| GET | `/api/conversations` | List all conversations |
| GET | `/api/conversation/{id}` | Get conversation history |
| DELETE | `/api/conversation/{id}` | Delete conversation |
| GET | `/api/info` | Application information |

### Tool-Using Agent

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/agent/execute` | Execute agent with tools |
| GET | `/api/agent/tools` | List available tools |

### Document Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/documents/upload` | Upload document |
| POST | `/api/documents/upload/bulk` | Bulk upload |
| POST | `/api/documents/upload/file` | File upload |
| POST | `/api/documents/upload/url` | Upload from URL |
| GET | `/api/documents/collections` | List collections |
| DELETE | `/api/documents/collection/{name}` | Delete collection |

### Streaming

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/stream/chat` | SSE streaming chat |
| GET | `/api/stream/active` | List active streams |
| GET | `/api/stream/monitor/{id}` | Monitor stream |
| POST | `/api/stream/inject/{id}` | Stream injection |
| POST | `/api/stream/replay/{id}` | Replay stream |
| DELETE | `/api/stream/clear` | Clear all streams |

### Embeddings

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/embeddings/generate` | Generate embedding |
| GET | `/api/embeddings/raw/{id}` | Get raw embedding |
| GET | `/api/embeddings/dump` | Dump all embeddings |
| POST | `/api/embeddings/search/by-vector` | Vector search |
| POST | `/api/embeddings/membership-inference` | Membership check |
| POST | `/api/embeddings/inversion-attack` | Inversion demo |
| GET | `/api/embeddings/statistics` | Collection stats |

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | User login |
| POST | `/api/auth/register` | User registration |
| POST | `/api/auth/register/admin` | Admin registration |
| GET | `/api/auth/session/{token}` | Get session |
| GET | `/api/auth/sessions` | List sessions |
| GET | `/api/auth/user/{id}` | Get user |
| PUT | `/api/auth/user/{id}` | Update user |
| GET | `/api/auth/users` | List users |
| POST | `/api/auth/password-reset` | Password reset |
| POST | `/api/auth/impersonate/{user}` | Impersonate user |

### RBAC

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/rbac/search` | Role-based search |
| GET | `/api/rbac/document/{id}` | Get document |
| POST | `/api/rbac/elevate` | Request elevation |
| GET | `/api/rbac/roles` | List roles |
| POST | `/api/rbac/check-access` | Check access |
| PUT | `/api/rbac/document/{id}/role` | Update document role |
| GET | `/api/rbac/admin/all-documents` | Admin access |
| GET | `/api/rbac/metadata-search` | Metadata search |

### Output Handling

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/output/render-html` | HTML rendering |
| POST | `/api/output/execute-command` | Command generation |
| POST | `/api/output/generate-sql` | SQL generation |
| POST | `/api/output/generate-code` | Code generation |
| POST | `/api/output/format-json` | JSON parsing |
| POST | `/api/output/log-entry` | Log entry |
| POST | `/api/output/template-render` | Template rendering |
| POST | `/api/output/file-path` | File path handling |
| POST | `/api/output/redirect` | URL redirect |

### Multi-Agent

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/agents/message/{agent}` | Message agent |
| POST | `/api/agents/chain` | Chain agents |
| POST | `/api/agents/delegate` | Delegate task |
| GET | `/api/agents/agents` | List agents |
| GET | `/api/agents/agent/{id}/prompt` | Get agent prompt |
| GET | `/api/agents/conversations` | List conversations |
| GET | `/api/agents/conversation/{id}` | Get conversation |
| POST | `/api/agents/admin-override` | Admin override |
| POST | `/api/agents/inject/{id}` | Inject context |
| DELETE | `/api/agents/conversation/{id}` | Clear conversation |

### MCP Protocol (WEF)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/mcp/servers` | List MCP servers (exposes secrets) |
| POST | `/api/mcp/invoke` | Invoke MCP tool |
| GET | `/api/mcp/secrets/dump` | Dump server secrets |
| GET | `/api/mcp/discover` | Discover MCP servers (SSRF) |

### Agent-to-Agent Protocol (WEF)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/a2a/agents` | List agents with cards |
| GET | `/api/a2a/agents/{id}` | Get agent card (leaks secrets) |
| POST | `/api/a2a/delegate` | Delegate task between agents |
| POST | `/api/a2a/impersonate/{id}` | Impersonate agent |
| POST | `/api/a2a/trust/add` | Add trust relationship |
| GET | `/api/a2a/trust/graph` | Get trust graph |

### Agent Ecosystem (WEF)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/ecosystem/process` | Process through agent pipeline |
| POST | `/api/ecosystem/memory/poison` | Poison agent memory |
| POST | `/api/ecosystem/cascade/simulate` | Simulate cascading failure |
| POST | `/api/ecosystem/goal/override` | Override agent goal |
| GET | `/api/ecosystem/state` | Get ecosystem state |

### Agent Marketplace (WEF)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/marketplace/agents` | List marketplace agents |
| GET | `/api/marketplace/agents/{id}` | Get agent details |
| GET | `/api/marketplace/agents/{id}/audit` | Audit agent (reveals backdoors) |
| POST | `/api/marketplace/agents/{id}/fake-reviews` | Add fake reviews |
| POST | `/api/marketplace/agents/{id}/install` | Install agent (no verification) |

### Agent Governance (WEF)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/governance/action/request` | Request action approval |
| POST | `/api/governance/hitl/auto-approve-all` | Bypass HITL |
| GET | `/api/governance/policies` | List policies |
| POST | `/api/governance/policies/activate/{id}` | Activate policy (injection) |
| GET | `/api/governance/audit/logs` | Get audit logs |
| POST | `/api/governance/audit/logs/tamper` | Tamper with logs |

### Agent Trust Protocols (`examples/`)

The Agent Trust Protocols — **ZTNP** (`draft-miller-ztnp-00`) and **ZTIP**
(`draft-miller-ztip-00`) — live in [`maul-py/examples/`](maul-py/examples/)
rather than `vulnerabilities/`, because each protocol ships with paired
**broken** and **solution** implementations:

- `broken.py` is the deliberately-wrong implementation (the exploit lab).
- `solution.py` is the spec-conformant implementation (the demonstrable fix).
- `scenarios.py` runs an attack against `broken`, replays the artifact
  through `solution`, and returns both decisions side-by-side with a
  `lesson` field citing the relevant draft section.

See [`maul-py/examples/README.md`](maul-py/examples/README.md) for the
directory structure and a quick tour.

#### ZTNP – Zero-Trust Negotiation Protocol

| Method | Endpoint | Track | Description |
|--------|----------|-------|-------------|
| GET  | `/api/examples/ztnp/broken/iks` | broken | List Issuers + IKS URLs |
| GET  | `/api/examples/ztnp/broken/iks/{iss_b64}` | broken | Issuer Key Set |
| POST | `/api/examples/ztnp/broken/iks/{iss_b64}/rotate` | broken | **V7**: unauthenticated key rotation |
| POST | `/api/examples/ztnp/broken/enroll` | broken | **V5**: trivial PA issuance |
| GET  | `/api/examples/ztnp/broken/pa/{jti}` | broken | Fetch issued PA |
| POST | `/api/examples/ztnp/broken/challenge` | broken | Issue challenge nonce |
| POST | `/api/examples/ztnp/broken/proof` | broken | **V1/V3/V6**: PERMIT issued without checks |
| GET  | `/api/examples/ztnp/broken/permits/{id}/validate` | broken | **V4**: no channel binding |
| GET  | `/api/examples/ztnp/solution/policy` | solution | Show Requester local policy |
| POST | `/api/examples/ztnp/solution/verify-pa` | solution | Standalone PA verifier |
| POST | `/api/examples/ztnp/solution/proof` | solution | Spec-conformant negotiation |
| GET  | `/api/examples/ztnp/solution/permits/{id}/validate` | solution | Sig + channel-binding check |
| GET  | `/api/examples/ztnp/scenarios` | scenarios | List walkthroughs |
| POST | `/api/examples/ztnp/scenarios/replay` | scenarios | PA replay (Section 5.5) |
| POST | `/api/examples/ztnp/scenarios/tier-confusion` | scenarios | Cross-issuer tier confusion (Section 4) |
| POST | `/api/examples/ztnp/scenarios/self-attest` | scenarios | Self-attested tier inflation (Section 11) |
| POST | `/api/examples/ztnp/scenarios/permit-lift` | scenarios | Permit lifted (Section 8.2) |
| POST | `/api/examples/ztnp/scenarios/iks-poison` | scenarios | Unauthenticated IKS rotation (Section 6.2) |

#### ZTIP – Zero-Trust Intent Protocol

| Method | Endpoint | Track | Description |
|--------|----------|-------|-------------|
| POST | `/api/examples/ztip/broken/intent/sign` | broken | Originator signs root Intent |
| POST | `/api/examples/ztip/broken/chain/wrap` | broken | **V2/V4**: no monotonicity, no depth cap |
| POST | `/api/examples/ztip/broken/chain/verify` | broken | **V1/V2/V3/V4/V7**: no checks |
| POST | `/api/examples/ztip/broken/token/intent-scoped` | broken | **V3**: intent_hash never recomputed |
| POST | `/api/examples/ztip/broken/operation/gate` | broken | **V3/V5**: trusts AS-issued scope |
| POST | `/api/examples/ztip/broken/behavioral/issue` | broken | Issue Behavioral Claims credential |
| POST | `/api/examples/ztip/solution/chain/verify` | solution | Section 3.3 rules 1–7 |
| POST | `/api/examples/ztip/solution/operation/gate` | solution | Recomputes intent_hash; enforces intent_scope |
| POST | `/api/examples/ztip/solution/behavioral/check` | solution | Requires evidence + public corpus |
| GET  | `/api/examples/ztip/scenarios` | scenarios | List walkthroughs |
| POST | `/api/examples/ztip/scenarios/confused-deputy` | scenarios | Prompt-injected confused deputy (Section 4) |
| POST | `/api/examples/ztip/scenarios/scope-expansion` | scenarios | Scope expansion mid-chain (Section 3.4) |
| POST | `/api/examples/ztip/scenarios/untrusted-root` | scenarios | Untrusted Originator at chain root (Section 3.3) |
| POST | `/api/examples/ztip/scenarios/depth-bomb` | scenarios | Deep-chain DoS (Section 3.5) |
| POST | `/api/examples/ztip/scenarios/behavioral-bluff` | scenarios | Claim without evidence (Section 5.1.1) |

References:
- ZTNP: <https://github.com/agent-trust-protocols/agent-trust-protocols/blob/main/drafts/ztnp/draft-miller-ztnp-00.md>
- ZTIP: <https://github.com/agent-trust-protocols/agent-trust-protocols/blob/main/drafts/ztip/draft-miller-ztip-00.md>

### OWASP Agentic AI (T1-T15)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET  | `/api/owasp-agentic/catalog` | List all 15 threats and endpoints |
| POST | `/api/owasp-agentic/t1/memory/write` | T1: Poison shared agent memory |
| GET  | `/api/owasp-agentic/t1/memory/read` | T1: Read poisoned memory |
| POST | `/api/owasp-agentic/t1/agent/act` | T1: Agent acts on poisoned memory |
| POST | `/api/owasp-agentic/t2/tool/dispatch` | T2: LLM-driven tool dispatch (no validation) |
| POST | `/api/owasp-agentic/t3/delegate` | T3: Unbounded scope delegation |
| POST | `/api/owasp-agentic/t3/escalate` | T3: Direct role escalation |
| POST | `/api/owasp-agentic/t4/fanout` | T4: Recursive fan-out explosion |
| POST | `/api/owasp-agentic/t4/loop` | T4: Unbounded iteration loop |
| POST | `/api/owasp-agentic/t5/cascade` | T5: Hallucination chain across agents |
| POST | `/api/owasp-agentic/t6/plan` | T6: Goal hijack via retrieved context |
| POST | `/api/owasp-agentic/t7/deceptive-execute` | T7: Report-vs-action divergence |
| GET  | `/api/owasp-agentic/t8/log` | T8: View mutable audit log |
| POST | `/api/owasp-agentic/t8/log/edit` | T8: Edit any audit entry |
| DELETE | `/api/owasp-agentic/t8/log/delete` | T8: Delete an audit entry |
| POST | `/api/owasp-agentic/t9/agent/send` | T9: Send message claiming any sender |
| POST | `/api/owasp-agentic/t10/hitl/submit` | T10: Submit HITL approval request |
| POST | `/api/owasp-agentic/t10/hitl/flood` | T10: Flood approval queue |
| POST | `/api/owasp-agentic/t10/hitl/auto-approve` | T10: Reviewer fatigue auto-approve |
| POST | `/api/owasp-agentic/t11/code/execute` | T11: NL→shell via LLM (RCE) |
| GET  | `/api/owasp-agentic/t12/bus` | T12: View inter-agent message bus |
| POST | `/api/owasp-agentic/t12/bus/tamper` | T12: Mutate in-flight messages |
| POST | `/api/owasp-agentic/t13/rogue/register` | T13: Register a rogue agent |
| GET  | `/api/owasp-agentic/t13/registry` | T13: Inspect agent registry |
| POST | `/api/owasp-agentic/t14/cross-agent` | T14: Cross-agent privilege abuse |
| POST | `/api/owasp-agentic/t15/manipulate` | T15: Hidden-objective user nudging |

Reference: <https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/>

---

## Database Schema

### Tables

#### conversations

```sql
CREATE TABLE conversations (
    id VARCHAR PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    seed_password TEXT NOT NULL
);
```

#### messages

```sql
CREATE TABLE messages (
    id SERIAL PRIMARY KEY,
    conversation_id VARCHAR REFERENCES conversations(id) ON DELETE CASCADE,
    role VARCHAR NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);
```

#### langchain_pg_embedding

```sql
CREATE TABLE langchain_pg_embedding (
    collection_id UUID,
    embedding VECTOR(1536),
    document TEXT,
    cmetadata JSONB
);
```

---

## Deployment Options

### Local Docker (Recommended)

```bash
git clone https://github.com/zivisai/MAUL.git
cd MAUL
cp .env.example .env
docker-compose build
docker-compose up
```

### Cloud Deployment

**AWS ECS / Fargate:**
1. Push images to ECR
2. Create ECS task definition
3. Configure Application Load Balancer
4. Set environment variables via Secrets Manager

**Google Cloud Run:**
1. Build and push to Artifact Registry
2. Deploy services to Cloud Run
3. Configure networking
4. Use Secret Manager for API keys

**Azure Container Apps:**
1. Push to Azure Container Registry
2. Create Container App environment
3. Deploy services
4. Use Key Vault for secrets

### Security Considerations

> **Warning:** This application is intentionally vulnerable.

1. **Network isolation** - Deploy in isolated VPC/network
2. **Access control** - Use VPN or IP allowlisting
3. **Monitoring** - Log all access attempts
4. **Cost controls** - Set OpenAI API spending limits
5. **Data** - Use only synthetic data
6. **Terms of service** - Require user agreement

---

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPENAI_API_KEY` | Yes | - | OpenAI API key |
| `SIM_PASSWORD` | No | (hidden) | Password for exercises |
| `PY_DEBUG` | No | `false` | Enable debugpy |
| `PGHOST` | No | `postgres` | PostgreSQL host |
| `PGDATABASE` | No | `vectors` | Database name |
| `PGUSER` | No | `postgres` | Database user |
| `PGPASSWORD` | No | `postgres` | Database password |

### Custom Datasets

Generate new synthetic data:
```bash
cd maul-py
python data/generate-docs.py
```

Or use the local data generator to create synthetic data.

---

## Development

### Local Setup

```bash
cd maul-py
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Debug Mode

```bash
PY_DEBUG=true docker-compose up maul-api-py
# Attach debugger to localhost:5678
```

### VS Code Configuration

```json
{
  "name": "Python: Remote Attach (Docker)",
  "type": "python",
  "request": "attach",
  "connect": {
    "host": "localhost",
    "port": 5678
  },
  "pathMappings": [
    {
      "localRoot": "${workspaceFolder}/maul-py",
      "remoteRoot": "/app"
    }
  ]
}
```

---

## Technology Stack

### Core Application

| Technology | Purpose |
|------------|---------|
| Python 3.11 | Runtime |
| FastAPI | Web framework |
| Uvicorn | ASGI server |
| OpenAI | LLM provider |
| LangChain | LLM framework |

### Data Layer

| Technology | Purpose |
|------------|---------|
| PostgreSQL | Primary database |
| pgvector | Vector similarity search |
| SQLAlchemy | ORM |
| asyncpg | Async PostgreSQL driver |

### Supporting Services

| Technology | Purpose |
|------------|---------|
| Redis | Cache (future use) |
| pgAdmin | Database admin |
| Docker | Containerization |

---

## Troubleshooting

### Common Issues

**API returns 500 errors:**
- Check OpenAI API key is valid
- Verify PostgreSQL is running: `docker-compose ps`
- Check logs: `docker-compose logs maul-api-py`

**Vector search returns no results:**
- Ensure ingestion completed in startup logs
- Verify pgvector extension is installed

**Database connection failures:**
- Wait for PostgreSQL to be ready
- Check network: `docker network ls`

### Logs

```bash
docker-compose logs -f              # All services
docker-compose logs -f maul-api-py  # API only
docker-compose logs -f postgres     # Database only
```

### Reset Environment

```bash
docker-compose down -v
docker-compose build --no-cache
docker-compose up
```

---

## License

[Apache License 2.0](LICENSE)

---

## Resources

- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP GenAI Security](https://genai.owasp.org/)
- [OWASP Agentic AI – Threats and Mitigations v1.0](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
- [WEF AI Agents in Action (2025)](https://www.weforum.org/publications/ai-agents-in-action-foundations-for-evaluation-and-governance-2025/)
- [LangChain Documentation](https://python.langchain.com/)
- [pgvector Documentation](https://github.com/pgvector/pgvector)
- [Model Context Protocol (MCP)](https://modelcontextprotocol.io/)
- [Agent-to-Agent Protocol (A2A)](https://github.com/google/A2A)

