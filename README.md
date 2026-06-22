# MAUL – Model & Agent Unsafe Lab

> **A deliberately vulnerable AI application for penetration testing training and security research.**

*Built and maintained by [ZIVIS](https://zivis.ai) as a public, open-source training range for AI and agentic security. MAUL is a target you stand up in isolation to learn on — not a tool for attacking real systems.*

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![OWASP](https://img.shields.io/badge/OWASP-LLM_Top_10-orange.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)

---

## ⚠️ Security Notice

**This application contains intentional security vulnerabilities.** It is designed for:

- Security professionals learning AI penetration testing
- Red teams practicing adversarial techniques
- Developers understanding AI security pitfalls
- Educators demonstrating LLM vulnerabilities
- CTF competitions and security workshops
- Anyone wanting to better understand AI security

**Do NOT deploy in production environments or expose to the public internet without proper access controls.**

> New here, or wondering whether a public repo full of vulnerabilities is safe and responsible? See **[THREAT-MODEL.md](THREAT-MODEL.md)** — why this exists, what it is *not*, and the safeguards built in.

---

## What is MAUL?

MAUL is an open-source, purpose-built vulnerable AI application that simulates real-world security flaws found in LLM-powered systems. It provides a safe, legal environment to practice attacks against modern AI applications.

### Key Features

| Feature | Description |
|---------|-------------|
| **50+ Vulnerabilities** | Comprehensive coverage of AI security flaws |
| **Web UI** | Interactive interface for all attack vectors |
| **RAG Pipeline** | Vulnerable retrieval-augmented generation |
| **Multi-Agent System** | Exploitable agent communication |
| **Tool-Using Agent** | Agent with dangerous capabilities |
| **Vector Database** | pgvector with embedding vulnerabilities |
| **Streaming (SSE)** | Server-sent events with security flaws |
| **Authentication** | Broken auth and session management |
| **Docker-based** | One-command deployment |

---

## Quick Start

### Prerequisites

- Docker & Docker Compose
- OpenAI API key

### 1. Clone & Configure

```bash
git clone https://github.com/zivisai/MAUL.git
cd maul
cp .env.example .env
# Edit .env and add your OpenAI API key
```

### 2. Launch

```bash
docker-compose build
docker-compose up
```

### 3. Access

| Service | URL | Purpose |
|---------|-----|---------|
| **Web UI** | http://localhost:8000 | Interactive interface |
| **API Docs** | http://localhost:8000/docs | Swagger documentation |
| **pgAdmin** | http://localhost:8080 | Database administration |
| **PostgreSQL** | localhost:5432 | Direct database access |

---

## Vulnerability Coverage

### OWASP LLM Top 10 (2025)

| # | Vulnerability | Status | Endpoints |
|---|---------------|--------|-----------|
| LLM01 | Prompt Injection | ✅ | `/api/ask`, `/api/agents/*` |
| LLM02 | Improper Output Handling | ✅ | `/api/output/*` |
| LLM03 | Data and Model Poisoning | ✅ | `/api/documents/*` |
| LLM04 | Unbounded Consumption | ✅ | All endpoints |
| LLM05 | Supply Chain Vulnerabilities | ⚠️ | Documented |
| LLM06 | Sensitive Information Disclosure | ✅ | `/api/ask`, `/api/info` |
| LLM07 | System Prompt Leakage | ✅ | `/api/ask`, `/api/agents/*` |
| LLM08 | Vector and Embedding Weaknesses | ✅ | `/api/embeddings/*` |
| LLM09 | Misinformation | ✅ | `/api/documents/*` |
| LLM10 | Excessive Agency | ✅ | `/api/agent/*` |

### OWASP Agentic AI Threats and Mitigations v1.0 (Feb 2025)

The OWASP GenAI Security Project's [Agentic AI – Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/) defines 15 threats (T1–T15) specific to autonomous, tool-using, multi-agent systems. MAUL exposes a focused, exploitable endpoint for each, all under `/api/owasp-agentic/*`. Use `GET /api/owasp-agentic/catalog` for the live index.

| # | Threat | Status | Endpoints |
|---|--------|--------|-----------|
| T1 | Memory Poisoning | ✅ | `/api/owasp-agentic/t1/memory/*`, `/t1/agent/act` |
| T2 | Tool Misuse | ✅ | `/api/owasp-agentic/t2/tool/dispatch` |
| T3 | Privilege Compromise | ✅ | `/api/owasp-agentic/t3/delegate`, `/t3/escalate` |
| T4 | Resource Overload | ✅ | `/api/owasp-agentic/t4/fanout`, `/t4/loop` |
| T5 | Cascading Hallucination Attacks | ✅ | `/api/owasp-agentic/t5/cascade` |
| T6 | Intent Breaking & Goal Manipulation | ✅ | `/api/owasp-agentic/t6/plan` |
| T7 | Misaligned & Deceptive Behaviors | ✅ | `/api/owasp-agentic/t7/deceptive-execute` |
| T8 | Repudiation & Untraceability | ✅ | `/api/owasp-agentic/t8/log/*` |
| T9 | Identity Spoofing & Impersonation | ✅ | `/api/owasp-agentic/t9/agent/send` |
| T10 | Overwhelming Human-in-the-Loop (HITL) | ✅ | `/api/owasp-agentic/t10/hitl/*` |
| T11 | Unexpected RCE & Code Attacks | ✅ | `/api/owasp-agentic/t11/code/execute` |
| T12 | Agent Communication Poisoning | ✅ | `/api/owasp-agentic/t12/bus/*` |
| T13 | Rogue Agents in Multi-Agent Systems | ✅ | `/api/owasp-agentic/t13/rogue/register` |
| T14 | Human Attacks on Multi-Agent Systems | ✅ | `/api/owasp-agentic/t14/cross-agent` |
| T15 | Human Manipulation | ✅ | `/api/owasp-agentic/t15/manipulate` |

### Additional Vulnerability Categories

| Category | Description | Endpoints |
|----------|-------------|-----------|
| **Authentication** | Broken authentication and session management | `/api/auth/*` |
| **Authorization** | Access control and privilege escalation flaws | `/api/rbac/*` |
| **Injection** | Command, SQL, and code injection via LLM | `/api/output/*` |
| **Streaming** | SSE stream security vulnerabilities | `/api/stream/*` |
| **Multi-Agent** | Agent communication and trust vulnerabilities | `/api/agents/*` |
| **XSS** | Cross-site scripting via LLM output | `/api/output/*` |
| **SSRF** | Server-side request forgery | Multiple endpoints |
| **Source Map Exposure** | Published source map leaks original front-end source & a hardcoded back-door token | `/static/js/*`, `/api/internal/debug-config` |

> **Source Map Exposure lab:** a self-contained, end-to-end demo of how a
> shipped `.map` file leaks your original source (and a hidden token) to anyone
> with DevTools. Walkthrough + fixes in
> [`maul-py/static/js/README.md`](maul-py/static/js/README.md).

---

## API Endpoints

### Core Chat
- `POST /api/ask` - Main RAG-enabled chat endpoint
- `GET /api/conversations` - List conversations
- `GET /api/conversation/{id}` - Get conversation history

### Tool-Using Agent
- `POST /api/agent/execute` - Execute agent with tools
- `GET /api/agent/tools` - List available tools

### Document Management
- `POST /api/documents/upload` - Upload document to vector store
- `POST /api/documents/upload/bulk` - Bulk document upload
- `POST /api/documents/upload/file` - File upload
- `POST /api/documents/upload/url` - Upload from URL
- `GET /api/documents/collections` - List collections

### Streaming
- `POST /api/stream/chat` - SSE streaming chat
- `GET /api/stream/active` - List active streams
- `GET /api/stream/monitor/{id}` - Monitor stream
- `POST /api/stream/inject/{id}` - Stream operations

### Embeddings
- `POST /api/embeddings/generate` - Generate embedding
- `GET /api/embeddings/raw/{id}` - Get raw embedding
- `GET /api/embeddings/dump` - Dump embeddings
- `POST /api/embeddings/membership-inference` - Membership check
- `POST /api/embeddings/inversion-attack` - Inversion demonstration

### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/register` - User registration
- `GET /api/auth/sessions` - Session management
- `GET /api/auth/users` - User listing
- `POST /api/auth/impersonate/{user}` - User impersonation

### RBAC
- `POST /api/rbac/search` - Role-based search
- `GET /api/rbac/document/{id}` - Document access
- `GET /api/rbac/roles` - Role listing
- `GET /api/rbac/admin/all-documents` - Admin access

### Output Handling
- `POST /api/output/render-html` - HTML rendering
- `POST /api/output/execute-command` - Command generation
- `POST /api/output/generate-sql` - SQL generation
- `POST /api/output/generate-code` - Code generation

### Multi-Agent
- `POST /api/agents/message/{agent}` - Message agent
- `POST /api/agents/chain` - Chain multiple agents
- `POST /api/agents/delegate` - Agent delegation
- `GET /api/agents/agent/{id}/prompt` - Agent information

### Agent Trust Protocols (ZTNP / ZTIP) — paired broken + solution
**ZTNP** (`draft-miller-ztnp-00`) and **ZTIP** (`draft-miller-ztip-00`) are
open trust-protocol drafts authored by ZIVIS for zero-trust agent negotiation
and intent verification. MAUL ships them in [`maul-py/examples/`](maul-py/examples/),
not `vulnerabilities/`, because each protocol ships with both a broken
implementation (the exploit lab) and a spec-conformant solution implementation
(the demonstrable fix) — so you can see exactly where a naive implementation
breaks and how the protocol closes the gap. See
[`maul-py/examples/README.md`](maul-py/examples/README.md) and the drafts linked
in [DOCS.md](DOCS.md).
- `GET  /api/examples/ztnp/scenarios` — list ZTNP walkthroughs
- `GET  /api/examples/ztip/scenarios` — list ZTIP walkthroughs
- `POST /api/examples/ztip/scenarios/confused-deputy` — broken ALLOWs `email.send`; solution DENIES `INTENT_SCOPE_MISMATCH`
- `POST /api/examples/ztnp/scenarios/replay` — broken issues PERMIT; solution DENIES `PA_BIND_MISMATCH`
- Broken endpoints under `/api/examples/{ztnp,ztip}/broken/*`; solutions under `/api/examples/{ztnp,ztip}/solution/*`
- See [DOCS.md](DOCS.md) for the full endpoint table

### OWASP Agentic AI Threats (T1–T15)
- `GET /api/owasp-agentic/catalog` - Live index of all 15 threats and their endpoints
- `POST /api/owasp-agentic/t1/memory/write` - Memory poisoning (T1)
- `POST /api/owasp-agentic/t2/tool/dispatch` - Tool misuse (T2)
- `POST /api/owasp-agentic/t3/escalate` - Privilege compromise (T3)
- `POST /api/owasp-agentic/t4/fanout` - Resource overload (T4)
- `POST /api/owasp-agentic/t5/cascade` - Cascading hallucination (T5)
- `POST /api/owasp-agentic/t6/plan` - Goal manipulation (T6)
- `POST /api/owasp-agentic/t7/deceptive-execute` - Deceptive behavior (T7)
- `POST /api/owasp-agentic/t8/log/edit` - Audit log tampering / repudiation (T8)
- `POST /api/owasp-agentic/t9/agent/send` - Identity spoofing (T9)
- `POST /api/owasp-agentic/t10/hitl/flood` - HITL fatigue attack (T10)
- `POST /api/owasp-agentic/t11/code/execute` - LLM-driven RCE (T11)
- `POST /api/owasp-agentic/t12/bus/tamper` - Inter-agent message tampering (T12)
- `POST /api/owasp-agentic/t13/rogue/register` - Rogue agent onboarding (T13)
- `POST /api/owasp-agentic/t14/cross-agent` - Cross-agent privilege abuse (T14)
- `POST /api/owasp-agentic/t15/manipulate` - Agent-to-human manipulation (T15)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Docker Network                               │
│                                                                      │
│  ┌──────────┐     ┌─────────────────────────────────────────────┐   │
│  │  Client  │────▶│              FastAPI Application             │   │
│  └──────────┘     │                 Port 8000                    │   │
│                   │  ┌─────────────────────────────────────────┐ │   │
│                   │  │           Vulnerability Modules          │ │   │
│                   │  │  ┌─────────┐ ┌─────────┐ ┌───────────┐  │ │   │
│                   │  │  │  Agent  │ │ Stream  │ │ Embedding │  │ │   │
│                   │  │  │  Tools  │ │   SSE   │ │  Attacks  │  │ │   │
│                   │  │  └─────────┘ └─────────┘ └───────────┘  │ │   │
│                   │  │  ┌─────────┐ ┌─────────┐ ┌───────────┐  │ │   │
│                   │  │  │  Auth   │ │  RBAC   │ │  Output   │  │ │   │
│                   │  │  │         │ │         │ │ Handling  │  │ │   │
│                   │  │  └─────────┘ └─────────┘ └───────────┘  │ │   │
│                   │  │  ┌─────────┐ ┌─────────┐               │ │   │
│                   │  │  │  Multi  │ │Document │               │ │   │
│                   │  │  │  Agent  │ │ Upload  │               │ │   │
│                   │  │  └─────────┘ └─────────┘               │ │   │
│                   │  └─────────────────────────────────────────┘ │   │
│                   └──────────────────┬──────────────────────────┘   │
│                                      │                               │
│                   ┌──────────────────▼──────────────────────────┐   │
│                   │        PostgreSQL + pgvector                 │   │
│                   │              Port 5432                       │   │
│                   └─────────────────────────────────────────────┘   │
│                                                                      │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐     │
│  │   pgAdmin   │    │    Redis    │    │     OpenAI API      │     │
│  │  Port 8080  │    │  Port 6379  │    │                     │     │
│  └─────────────┘    └─────────────┘    └─────────────────────┘     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
maul/
├── docker-compose.yml
├── .env.example
├── README.md
├── DOCS.md
├── CONTRIBUTING.md
├── LICENSE
└── maul-py/
    ├── Dockerfile
    ├── requirements.txt
    ├── main.py
    ├── db.py
    ├── langchain_ingest.py
    ├── static/
    │   └── index.html
    ├── vulnerabilities/
    │   ├── __init__.py
    │   ├── agent_tools.py
    │   ├── document_upload.py
    │   ├── streaming.py
    │   ├── embeddings.py
    │   ├── auth.py
    │   ├── output_handling.py
    │   ├── multi_agent.py
    │   └── rbac.py
    └── data/
        ├── int_db.py
        └── generate-docs.py
```

---

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPENAI_API_KEY` | Yes | - | OpenAI API key |
| `SIM_PASSWORD` | No | (hidden) | Password for exercises |
| `PY_DEBUG` | No | `false` | Enable debugpy |

---

## Documentation

- **[DOCS.md](DOCS.md)** – Technical documentation
- **[THREAT-MODEL.md](THREAT-MODEL.md)** – Why publishing a vulnerable app is safe & responsible
- **[CONTRIBUTING.md](CONTRIBUTING.md)** – Contribution guidelines
- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc

---

## Debug Mode

```bash
PY_DEBUG=true docker-compose up maul-api-py
# Attach debugger to localhost:5678
```

---

## Dataset

Synthetic financial data can be generated locally:

Generate custom data:
```bash
cd maul-py && python data/generate-docs.py
```

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

[Apache License 2.0](LICENSE)

---

## Resources

- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP GenAI Security](https://genai.owasp.org/)
- [OWASP Agentic AI – Threats and Mitigations v1.0 (Feb 2025)](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)

