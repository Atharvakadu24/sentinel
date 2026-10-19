# Sentinel — AI-Powered Code Review & Security Platform

Sentinel is a code review and security triage platform designed for pull-request workflows. It combines a fast, deterministic static analysis layer (Semgrep and Gitleaks) with a constrained, evidence-grounded LLM second reviewer to deliver actionable, high-signal feedback directly to developers.

---

## Overview

Security issues are cheapest to remediate at code-review time. However, development teams on small projects often lack dedicated AppSec staff, and traditional static analysis tools flood pull requests with overwhelming false-positive noise that developers routinely ignore. Conversely, unconstrained AI review bots often hallucinate non-existent issues, miss real syntax bugs, or cite fictitious line numbers.

Sentinel addresses this with a planned **three-tier verification pipeline**:
1. **Deterministic Static Analysis:** Proven open-source scanners (Semgrep Community Edition and Gitleaks) identify structural vulnerability patterns and hardcoded secrets.
2. **Grounded AI Second Reviewer:** An LLM acts as an untrusted second reviewer with no network or tool authority. Every claim it generates must quote real code that Sentinel machine-verifies against the actual file. Unverifiable claims are automatically dropped.
3. **Diff-Scoped Lifecycle Tracking:** Issues touching modified lines (`in_diff=true`) are highlighted first, while persistent SHA-256 fingerprints ensure developer triage decisions (dismissed, accepted risk) survive across subsequent commits and pushes.

---

## Current Status

- **Implemented & Verified:** Repository foundation, environment configuration templates ([`.env.example`](.env.example)), root ignore rules ([`.gitignore`](.gitignore)), architecture blueprints ([`docs/architecture.md`](docs/architecture.md)), and local PostgreSQL 16 container orchestration ([`docker-compose.yml`](docker-compose.yml)).
- **Planned / In Development:** The core analysis engine, scanner adapters, worker queue, REST API, AI review service, GitHub integration, React dashboard, and evaluation harness described below represent target functionality defined in the system design blueprint.

---

## Intended Workflow

```
[Developer Opens PR]
         │
         ▼
[GitHub Webhook / HMAC Verification] ──► [FastAPI API]
                                               │
                                               ▼  (Single Transaction)
                                      [PostgreSQL DB & Jobs Queue]
                                               │
                                               ▼  (Claim: FOR UPDATE SKIP LOCKED)
                                      [Background Worker]
                                               │
               ┌───────────────────────────────┼───────────────────────────────┐
               ▼                               ▼                               ▼
       [Source Fetching]              [Deterministic Scan]            [Bounded AI Review]
  (Changed files only; temp dir)      (Semgrep + Gitleaks)            (Schema-validated,
                                               │                       evidence-grounded)
                                               ▼                               │
                                       [Normalization] ◄───────────────────────┘
                                       (Deduplication & v1 Fingerprints)
                                               │
                                               ▼
                              [Upsert Single PR Summary Comment]
                                               │
                                               ▼
                                 [Review in React Dashboard]
```

---

## Target Architecture & Technology Stack

Sentinel is designed as a **modular monolith** with clean ports and adapters at external boundaries, keeping business logic separated from third-party infrastructure.

> **Scope Note:** The technology stack below describes the planned target implementation defined in the system design blueprint. Only the repository foundation, environment configuration templates, and local container orchestration have been implemented and verified so far.

- **Backend:** Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2.0 (sync engine, psycopg 3), and Alembic migrations, managed with [`uv`](https://github.com/astral-sh/uv).
- **Database & Job Queue:** PostgreSQL 16. The background job queue uses a dedicated `jobs` table claimed with `FOR UPDATE SKIP LOCKED`, providing transactional job enqueuing without requiring Redis.
- **Static Scanners:** Semgrep Community Edition (CLI with curated, vendored rulesets) and Gitleaks (CLI secret detection).
- **AI Review Service:** Provider-agnostic client adapter (Anthropic API / Google Gemini) utilizing forced structured outputs and server-side schema re-validation.
- **Frontend Dashboard:** React 18, TypeScript, Vite, Tailwind CSS, shadcn/ui (Radix primitives), and TanStack Query.
- **GitHub Integration:** GitHub App with fine-grained repository permissions and short-lived installation tokens.

For complete architectural specifications, ER diagrams, and data flows, see [docs/architecture.md](docs/architecture.md).

---

## Security Design Principles & Intended Safeguards

Sentinel's architecture explicitly differentiates between application-level safeguards and environment-enforced security boundaries:

- **Environment-Enforced Boundaries vs. Application Safeguards:** Prompts, application logic, and code-level checks alone do not constitute security boundaries. Critical safeguards—such as network isolation for scanner subprocesses and the LLM, read-only container filesystems, dropped execution privileges, and process resource limits (CPU, memory, wall-clock)—must be strictly enforced by the execution and container environment rather than assumed from application code or prompt instructions alone.
- **Zero Arbitrary Execution:** Sentinel is architected never to build, run, or execute submitted code. Scanners only parse source files as static text data within ephemeral, constrained temporary directories.
- **Intended Zero-Secret Disclosure:** Detected secrets are designed to be hashed using server-side HMAC-SHA256 fingerprint anchors and redacted across storage, logs, LLM prompts, and pull-request comments before persistence or display.
- **Prompt Injection Safeguards:** The LLM client is designed as an unprivileged component with no tools, credentials, or network authority. While prompt delimiters reduce injection risk, true boundary defense relies on deterministic server-side schema re-validation, evidence substring grounding against real files, and output sanitization.
- **Enforced Tenant Isolation Design:** All data queries are planned to enforce tenancy strictly scoped through `projects.owner_user_id`. Unauthorized cross-tenant requests return `404` to avoid confirming resource existence.
- **Secure Session Management:** Authentication is designed around server-side sessions stored as SHA-256 hashes, transmitted via `HttpOnly`, `Secure`, `SameSite=Lax` cookies with strict CSRF Origin validation.

---

## Local Development Setup

### Prerequisites

Ensure the following tools are installed on your workstation:
- **Python:** 3.12+ (managed with `uv`)
- **Node.js:** 20+ (with `npm` or `pnpm`)
- **Docker & Docker Compose:** For running the local PostgreSQL container

### 1. Environment Configuration

Copy the environment template to create a local `.env` file:
```powershell
cp .env.example .env
```

The template [`.env.example`](.env.example) contains documented configurations and safe local defaults. Update the placeholders (such as secret keys and API credentials) for your development environment.

### 2. Start Local PostgreSQL Database

Launch the PostgreSQL 16 container using Docker Compose:
```powershell
docker compose up -d postgres
```

Verify that the database container is running and healthy:
```powershell
docker compose ps
```

To stop the database service:
```powershell
docker compose down
```

---

## Planned Capabilities

The platform capabilities planned in the system design blueprint include:

- **Core Analysis & Fingerprinting:** Canonical Pydantic finding schema, unified diff hunk parser, and stable `v1` SHA-256 fingerprinting that excludes volatile line numbers.
- **Deterministic Scanner Subprocesses:** Sandboxed execution adapters for Semgrep and Gitleaks with timeouts, memory caps, and secret redaction.
- **Transactional Job Queue:** PostgreSQL-backed poller using `FOR UPDATE SKIP LOCKED` with heartbeats, worker leases, and automatic failure recovery.
- **Grounded AI Review:** Structured response validation, verbatim evidence substring matching, token quotas, and prompt-injection mitigations.
- **REST API & Session Auth:** FastAPI endpoints for manual code scanning, finding management, CSRF validation, and GitHub OAuth sessions.
- **GitHub App & PR Automation:** Webhook receiver with HMAC verification, diff-scoped finding analysis, and single upserted PR summary comments.
- **Review Dashboard:** React SPA with finding status workflows (open, fixed, accepted, dismissed, false positive) and optimistic UI updates.
- **Evaluation Harness & Benchmarks:** Standalone CLI tool and labeled corpus to measure precision, recall, and AI claim validity empirically.

---

## Testing & Evaluation Approach (Planned)

Sentinel's architecture prioritizes measurable verification and reproducibility:

- **Unit & Integration Tests:** Planned test coverage across canonical schema normalization, diff parsing algorithms, the `v1` fingerprint engine, tenant isolation boundaries, and scanner subprocess adapters.
- **Evaluation Harness & Labeled Corpus:** A planned CLI harness designed to run over a curated corpus of vulnerable and safe code samples. The harness will report:
  - Scanner-only vs. Scanner + AI precision and recall.
  - Evidence localization accuracy.
  - AI claim validity rate (valid grounded claims vs. ungrounded rejections).
  - Schema error and retry rates.

---

## Honest Positioning

Sentinel is developed as a portfolio MVP and security engineering prototype. It demonstrates how to integrate deterministic tooling, transactional queues, and grounded LLM reviews safely. It is **not** an enterprise compliance certification tool and does not replace human security reviews or specialized penetration testing.

---

## Documentation

- [Architecture Overview](docs/architecture.md)
- [System Design & Implementation Blueprint (DOCX)](docs/Sentinel%20%E2%80%94%20System%20Design%20%26%20Implementation%20Blueprint.docx)
