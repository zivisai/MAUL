# Why a Deliberately Vulnerable App Is Safe to Publish

MAUL contains intentional security vulnerabilities. This document explains why
publishing it openly is safe and responsible — and what we did to keep it that
way. If you are evaluating MAUL (or ZIVIS) and your first reaction is "should a
repository full of exploits be public?", this is for you.

## The short version

MAUL is a **training range**, not a weapon. It is a target you stand up in
isolation to learn on — the same category as
[OWASP Juice Shop](https://owasp.org/www-project-juice-shop/),
[WebGoat](https://owasp.org/www-project-webgoat/), and
[DVWA](https://github.com/digininja/DVWA), extended to the AI- and agent-specific
threats defined by the
[OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/),
the [OWASP Agentic AI Threats & Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/),
and the [WEF AI Agents in Action](https://www.weforum.org/publications/ai-agents-in-action-foundations-for-evaluation-and-governance-2025/) report.

Publishing vulnerable-by-design applications for education is an established,
respected practice in security. The defensive value — teaching engineers and
decision-makers what these failures actually look like — is well understood and
long-standing.

## What MAUL is *not*

- **Not an exploit kit.** MAUL does not contain tooling that targets, scans, or
  attacks third-party systems. Every vulnerability lives inside MAUL's own
  endpoints and only affects a MAUL instance you run yourself.
- **Not a zero-day dump.** The vulnerabilities are well-known, publicly
  documented classes (prompt injection, excessive agency, insecure output
  handling, etc.) mapped to public frameworks. Nothing here is a novel,
  undisclosed attack against a real product.
- **Not a live service.** There is no hosted, internet-facing instance. You run
  it locally or in an isolated network.

## Safeguards we built in

- **No real secrets.** Every credential in the repo is explicitly fake
  (`sk-FAKE-…-NOTREAL`, AWS's published `AKIAIOSFODNN7EXAMPLE` example key,
  etc.). There are no live keys to leak.
- **Synthetic data only.** All "PII" and financial profiles are generated
  locally and fictitious. No real customer or personal data is present.
- **Loud, in-product warnings.** The README, the web UI, and this document all
  state that MAUL is intentionally vulnerable and for isolated training use only.
- **Responsible disclosure path.** [SECURITY.md](.github/SECURITY.md) separates
  *intentional* vulnerabilities (features, do not report) from *unintentional*
  ones (real bugs, leaked secrets, supply-chain issues — please report privately).
- **Safe-usage guidance.** We document network isolation, no-production-data,
  access-control, and API-spend-limit practices for anyone running it.

## How to run it safely

1. Run it in an isolated network or VPC — never expose it to the public internet.
2. Use only the synthetic data provided, or other synthetic data. Never load real
   customer data or credentials.
3. Use a dedicated LLM API key with a spending limit (the unbounded-consumption
   scenarios can otherwise run up cost).
4. Restrict access to people who know it is a deliberately vulnerable lab.

## Reporting

Found something that looks like a *real*, unintentional problem — a genuine leaked
credential, a supply-chain issue, or a Docker misconfiguration that could harm a
user running MAUL? Please follow [SECURITY.md](.github/SECURITY.md) and email
trustrepo@zivis.ai rather than opening a public issue. Intentional vulnerabilities
documented in [DOCS.md](DOCS.md) are features and do not need to be reported.

---

*Maintained by [ZIVIS](https://zivis.ai). MAUL exists so that the failures of AI
and agentic systems can be seen, understood, and defended against — on a range
built for exactly that purpose.*
