# Sentinel — Architecture Overview

> **Source of Truth:** This overview synthesizes the system design specified in [`docs/Sentinel — System Design & Implementation Blueprint.docx`](./Sentinel%20%E2%80%94%20System%20Design%20%26%20Implementation%20Blueprint.docx) (v1.0).

---

## 1. Executive Summary & Purpose

Sentinel is an AI-powered code review and security triage platform specifically designed for pull-request workflows.

### Core Problems Addressed
- Security issues are cheapest to fix at code-review time.
- Traditional scanners produce overwhelming false-positive noise.
- Unconstrained AI reviewers hallucinate non-existent issues, miss real bugs, or invent code lines.

### Solution & Key Differentiators
1. **Diff-Scoped Triage:** Prioritizes issues touching changed lines (`in_diff=true`) while distinguishing pre-existing issues.
2. **Deterministic-First Layer:** Relies on trusted deterministic engines (Semgrep Community Edition + Gitleaks) for rule-based vulnerability and secret detection.
3. **Constrained, Grounded AI Second Reviewer:** The LLM has no tools, credentials, or network authority. Its output is strictly validated against a Pydantic JSON schema and physically grounded against actual line numbers and substring evidence. Unverifiable claims are discarded.
4. **Persistent Lifecycle Tracking:** Findings maintain a stable identity across scans using a versioned `v1` SHA-256 fingerprint (excluding line numbers), ensuring user dismissals and accepted risks persist across subsequent commits.

---

## 2. High-Level Architecture

Sentinel is structured as a **modular monolith** with clean ports and adapters at external boundaries.

```
                      +-----------------------------+
                      |          React SPA          |
                      |   (Vite + TS + shadcn/ui)   |
                      +--------------+--------------+
                                     |
                                     | HTTPS /api (Same-Origin)
                                     v
+------------------+  webhooks  +----+------------------------+
|    GitHub API    | ---------> |      FastAPI API Process    |
|  & GitHub App    |            | (Auth, CRUD, Enqueue, /wh)  |
+------------------+            +----+------------------------+
         ^                           |
         |                           | Single Transaction
         |                           v
         |            +--------------+--------------+
         |            |        PostgreSQL 16        |
         |            | (Tables: scans, jobs, etc.) |
         |            +--------------+--------------+
         |                           ^
         |                           | Claim (FOR UPDATE SKIP LOCKED)
         |                           v
         |              +------------+------------+
         |              |      Worker Process     |
         |              | (Execution Pipeline)    |
         |              +----+-------+-------+----+
         |                   |       |       |
         | (PR comment)      v       v       v
         +-------------+  Semgrep Gitleaks  LLM Client
                                            (Anthropic/Gemini)
```

### Components
- **API (`api` process):** Handles authentication (GitHub OAuth session cookies), user/project management, manual scan ingestion, webhook receipt, and finding queries. Never executes scanners or LLMs directly.
- **Worker (`worker` process):** Polls the PostgreSQL `jobs` table using `FOR UPDATE SKIP LOCKED`. Manages the analysis pipeline, subprocess execution, LLM grounding, deduplication, database persistence, and GitHub comment reporting.
- **Database (PostgreSQL 16):** Serves as both the system of record and the transactional queue.
- **Engines:**
  - **Semgrep:** Pattern/AST rule-based vulnerability detection with vendored rules.
  - **Gitleaks:** Secret and API credential detection with zero secret disclosure (HMAC-SHA256 fingerprint anchors and redaction).
  - **LLM Client:** Constrained structured-output second reviewer.

---

## 3. End-to-End Analysis Pipeline

When a scan is triggered (via PR webhook or manual multi-file upload):

1. **Transactional Enqueue:** A `scans` row (`status=queued`) and a `jobs` row are inserted in a single database transaction.
2. **Job Claiming:** A worker claims the job with a lease (`FOR UPDATE SKIP LOCKED`) and updates scan status to `running`.
3. **Source Fetching & Isolation:** Changed files are written to an isolated temporary directory (`/tmp/sentinel/...`) under randomized file handles (e.g. `f0001.py`). Repository code is never executed.
4. **Deterministic Analysis:** Semgrep and Gitleaks run as sandboxed subprocesses with CPU, memory, and wall-clock limits. Snippets are reconstructed from Sentinel's copy of the files with secrets redacted.
5. **Diff Mapping:** Hunks from GitHub PR diffs are parsed into added-line sets to determine whether findings fall `in_diff`.
6. **Bounded AI Review:** If enabled and within quota, the top-ranked changed files are provided to the LLM inside delimited windows with explicit line prefixes (`L123| code`).
7. **Grounding & Validation:**
   - Server-side schema validation (Pydantic `extra="forbid"`).
   - Evidence substring verification: quoted snippets must match real file content within ±10 lines or be relocated/discarded.
   - Severity/confidence capped at `medium`.
8. **Deduplication & Persistence:**
   - Fingerprint calculation: `sha256("v1|" + rule_key + "|" + normalized_path + "|" + anchor + "|" + occ)`.
   - Persistent `findings` rows upserted.
   - Per-scan occurrences stored in `scan_findings`.
   - Temporary source files immediately wiped from disk and payload nulled.
9. **Reporting:** If analyzing a GitHub pull request, a single formatted summary comment is upserted on the PR.

---

## 4. Trust Boundaries & Security Minimums

1. **Never Execute Code:** Scanned repositories are never built, executed, or tested. Files are strictly parsed as data.
2. **Secret Redaction:** Plaintext secrets detected by Gitleaks or redactor filters are never copied to database fields, logs, LLM prompts, or GitHub comments.
3. **Prompt Injection Boundaries:** Delimiters, strict schema re-validation, lack of tools/credentials, and evidence grounding ensure untrusted source code cannot compromise the system or hallucinate valid findings.
4. **Tenant Isolation:** Every query strictly enforces tenant isolation scoped through `projects.owner_user_id`. Direct object references return `404` for unauthorized entities.
5. **Session Security:** Server-side sessions keyed by random SHA-256 hashed tokens transmitted via `HttpOnly`, `Secure`, `SameSite=Lax` cookies with strict CSRF Origin validation.

---

## 5. Blueprint Alignment & Missing Sections Note

> [!NOTE]
> **Design Decision on Truncated Sections:**
> The primary system design blueprint (`docs/Sentinel — System Design & Implementation Blueprint.docx`) covers Sections 1 through 12.3 in exhaustive detail. Sections 13 (Summary metrics), 14 (Evaluation harness CLI), and 19 (Honest positioning) are referenced in the text but truncated from the export.
>
> In accordance with project instructions:
> - All implementations strictly follow the explicit requirements in Sections 1–12.3.
> - Any evaluation harness implementation (FR-15) and metrics synthesis (FR-11) is treated as a **project design decision** modeled faithfully on the principles in Sections 2.5 and 11.10.
