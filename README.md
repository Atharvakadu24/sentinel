# Sentinel — AI-Powered Code Review & Security Platform

Sentinel reviews pull-request changes for software bugs and security vulnerabilities. It combines a fast, deterministic static analysis layer (Semgrep and Gitleaks) with a constrained, evidence-grounded LLM second reviewer to deliver actionable, high-signal feedback directly into developer workflows.

---

## Current Status: Milestone 1 (Repository Foundation)

> **Implementation Note:** Sentinel is currently in its initial setup phase.
> - **Milestone 1 (Current):** Repository foundation, environment configurations, documentation, and local PostgreSQL container orchestration.
> - **Next Milestones:** Core domain schemas & fingerprint engine, scanner adapters, worker queue, and API endpoints.
> - *No application code, scanner execution, or AI integrations are active yet.*

---

## Why Sentinel?

Security issues are cheapest to remediate at review time, but developers on small teams often lack dedicated AppSec resources, and traditional static analysis tools flood pull requests with noisy false positives.

Sentinel addresses this by focusing on three core capabilities:

1. **Diff-Scoped Signal:** Distinguishes between new issues introduced by the PR (`in_diff=true`) and pre-existing codebase issues.
2. **Grounded AI Second Reviewer:** The LLM operates with zero tools, zero network authority, and no credentials. Every finding it claims must quote exact source code that Sentinel physically re-locates in the target file. Unverifiable claims are automatically discarded.
3. **Stable Fingerprint Lifecycle:** Findings are identified using a versioned `v1` SHA-256 fingerprint that tracks issues across commits even when unrelated lines change. When a developer dismisses an issue or accepts a risk, that decision persists across future pushes.

---

## Honest Positioning

Sentinel is designed as a deployed portfolio MVP and prototype platform. It demonstrates how to combine deterministic tooling, transactional queues, and grounded LLM reviews safely. It is **not** a certified enterprise compliance scanner and should not be relied upon as a replacement for comprehensive human security audits.

---

## System Architecture

Sentinel is implemented as a **modular monolith** with clean ports and adapters:

- **Backend:** Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2.0 (sync engine, psycopg 3), Alembic migrations, packaged with `uv`.
- **Database & Queue:** PostgreSQL 16. The background job queue uses a dedicated `jobs` table claimed with `FOR UPDATE SKIP LOCKED`, providing transactional job enqueuing without requiring Redis.
- **Static Scanners:** Semgrep Community Edition (curated vendored rules) and Gitleaks (CLI secret detection with zero-disclosure HMAC anchors and redaction).
- **AI Reviewer:** Provider-agnostic client adapter (Anthropic API / Google Gemini) with structured output schema validation.
- **Frontend:** React 18, TypeScript, Vite, Tailwind CSS, shadcn/ui (Radix primitives), and TanStack Query.
- **GitHub Integration:** GitHub App with short-lived, least-privilege installation tokens and upserted PR summary comments.

For in-depth architecture diagrams and data flows, see [docs/architecture.md](docs/architecture.md).

---

## Project Structure

```text
sentinel/
├── .github/              # Continuous integration workflows
├── backend/              # Python FastAPI API & worker execution pipeline
├── frontend/             # React + TypeScript + Vite SPA
├── rules/                # Vendored Semgrep rule definitions with CWE/OWASP metadata
├── evaluation/           # Evaluation harness and labeled vulnerability corpus
├── docs/                 # System architecture overview & blueprint documentation
├── docker-compose.yml    # Local PostgreSQL 16 development database
├── .env.example          # Environment variable schema with security documentation
├── .gitignore            # Multi-layer gitignore (Python, Node, secrets, scanner caches)
└── README.md             # Project overview, architecture, and developer guide
```

---

## Development Prerequisites

Before running Sentinel locally, ensure the following tools are installed:

- **Python:** 3.12+ (managed with [`uv`](https://github.com/astral-sh/uv))
- **Node.js:** 20+ (with `npm` or `pnpm`)
- **Docker & Docker Compose:** For running the local PostgreSQL database

---

## Local Development Quickstart

### 1. Configure Environment Variables
Copy the configuration template and generate development secrets:
```powershell
cp .env.example .env
```
*(Review `.env` to ensure database credentials and settings match your local environment. Default values in `.env.example` are pre-configured for local Docker Compose).*

### 2. Start the Local PostgreSQL Database
Run the local PostgreSQL 16 container:
```powershell
docker compose up -d postgres
```

Verify that the database container is healthy:
```powershell
docker compose ps
```

To stop the database container when finished:
```powershell
docker compose down
```

---

## Planned Implementation Roadmap

| Milestone | Focus | Deliverables |
| :--- | :--- | :--- |
| **Milestone 1** (Done) | Repository Foundation | `.gitignore`, `.env.example`, `docker-compose.yml`, architecture docs, baseline README |
| **Milestone 2** | Domain Logic & Schemas | Canonical finding schema, `v1` SHA-256 fingerprint engine, diff parser, SQLAlchemy models |
| **Milestone 3** | Scanner Subprocess Engine | Semgrep & Gitleaks adapters, sandboxing limits, secret redactor, unit test suite |
| **Milestone 4** | Job Queue & Worker | PostgreSQL `FOR UPDATE SKIP LOCKED` poller, heartbeat reaper, execution pipeline |
| **Milestone 5** | REST API & Manual Analysis | FastAPI routers, session authentication, CSRF defense, manual file submission (FR-2) |
| **Milestone 6** | Grounded AI Reviewer | Schema validator, evidence substring grounding, token quotas, prompt-injection defense |
| **Milestone 7** | GitHub App & PR Scans | Webhook receiver, HMAC verification, diff-scoped analysis, PR summary reporter |
| **Milestone 8** | Web Dashboard (Frontend) | React SPA, finding triage workflow, optimistic status updates, scan progress polling |
| **Milestone 9** | Evaluation Harness | Labeled corpus test runner, CLI precision/recall metrics reporting |

---

## Security Principles

- **Zero Arbitrary Execution:** Sentinel never builds, runs, or executes submitted code. Source code is only ever parsed by static analysis tools.
- **Zero Secret Disclosure:** Detected API keys and credentials are HMAC-fingerprinted and redacted before persisting or displaying findings.
- **Input Sanitization:** User files, diffs, and AI-generated outputs are treated as untrusted and rendered strictly as text nodes in the frontend.

---

## Documentation

- [Architecture Overview](docs/architecture.md)
- [System Design & Implementation Blueprint (DOCX)](docs/Sentinel%20%E2%80%94%20System%20Design%20%26%20Implementation%20Blueprint.docx)
