# Aegis AI Security

An open-source web platform for **authorized** security assessment of
Generative AI applications — their models, prompts, retrieval layers,
agents, tools, and supporting APIs — producing defensible, reproducible,
framework-mapped findings.

This is not a probe library and not a UI prototype. The full design —
mission, non-goals, safety/payload policy, the scope-and-authorization
engine, determinism/ASR methodology, domain model, and the phased build
plan — lives in **[`docs/BUILD_SPEC.md`](docs/BUILD_SPEC.md)**. Read that
first; this README is the practical "how do I run it" companion.

**Current status: through Phase 10, plus Phases 14–16.** What works end to
end today: the scope/authorization engine and its gated transport (the single
outbound control point), target adapters and OpenAPI discovery, run
orchestration with cancellation and live progress, 16 API probes, 11 AI
probes measured with Wilson-interval attack success rates against their own
controls, the SAST/SCA/secrets/IaC engines, the AI assistant layer (drafts
only, never execution), risk-scored findings with stable fingerprints, and
content-addressed evidence plus reports in Markdown, HTML, PDF, JSON, SARIF
2.1.0 and CSV, and a remediation board with a retest workflow that reports
reproduced / not reproduced / not tested with the evidence from either side.

There is also an `aegis-ai` CLI and a CI security gate with documented exit
codes — see [`docs/cicd.md`](docs/cicd.md).

Still to come: plugins (Phase 11), the demo lab (12), the release
documentation (13), DAST (15), and the HTMX dashboard (17) — the shipped
frontend is still the auth scaffold only. [`docs/roadmap.md`](docs/roadmap.md) records exactly
what's built versus deferred, and why, phase by phase.

## Why this exists

The open-source AI red-teaming space already has strong tools — garak,
PyRIT, promptfoo, DeepTeam, Giskard. None of them combine a hard
authorization/scope boundary, tamper-evident evidence, cross-tool finding
normalization, and statistically honest (ASR + confidence interval)
reporting into one assessment workflow. See `docs/BUILD_SPEC.md` §1.1 for
the full comparison, and `docs/comparison.md` (once written) for where
those tools are still better.

## Architecture

```
Browser ──▶ Next.js ──▶ FastAPI ──▶ PostgreSQL
                             │
                             ▼
                           Redis ──▶ Celery Workers ──▶ Security Testing Engine ──▶ Authorized Target
```

- **Frontend:** Next.js 16 (App Router), React 19, TypeScript, Tailwind CSS,
  TanStack Query, React Hook Form + Zod.
- **Backend:** Python 3.12, FastAPI, SQLAlchemy 2 (async), Alembic,
  PostgreSQL, Redis, Celery, Argon2id password hashing, JWT sessions.
- **Deployment:** Docker Compose (`frontend`, `backend`, `worker`,
  `postgres`, `redis`).

Full layering rules and the reasoning behind PostgreSQL/Redis/Celery from
Phase 1 (rather than an MVP-first SQLite path) are in `docs/BUILD_SPEC.md`
§4 and `docs/decisions/0001-storage-and-product-shape.md`.

## Quickstart

```bash
cp .env.example .env
docker compose up --build
```

Then open <http://localhost:3000>, register an account, and create an
organization. The web UI stops there — targets, runs, findings, reports and
evidence exist as API endpoints, not yet as pages (the dashboard is Phase
17), so drive them against <http://localhost:8000/docs> for now. Nothing will
reach a target until you record an authorization grant and Rules of
Engagement for it; that refusal is the point.

> **Note on this sandbox's own validation:** the application was validated
> end to end by running the backend under `uvicorn` against a live
> PostgreSQL + Redis and the frontend under `next start` against that
> backend, driving the real register → login → create-organization flow
> over HTTP. Actually building the Docker images was not possible in the
> environment this was built in (Docker Hub pulls are blocked by that
> sandbox's network policy — see `docs/roadmap.md`); verify the
> `docker compose up --build` path in a normal environment before relying
> on it, though the CI workflow itself never pulls from Docker Hub, so it is
> unaffected.

### Local development without Docker

```bash
# Backend
cd backend
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
export DATABASE_URL=postgresql+asyncpg://<user>:<password>@localhost:5432/aegis
export REDIS_URL=redis://localhost:6379/0
alembic upgrade head
uvicorn app.main:app --reload

# Frontend (separate shell)
cd frontend
npm install
npm run dev
```

## Testing

```bash
make test-backend   # pytest, against a real Postgres — see backend/tests/conftest.py
make test-frontend  # vitest
make lint            # ruff + eslint
make typecheck       # mypy --strict + tsc --noEmit
```

Backend: 19 tests covering registration, login/logout, session cookies vs.
bearer tokens, RBAC (owner/admin/security_engineer/analyst/viewer), and
cross-organization tenant isolation. 92% statement coverage, `ruff check`
clean, `mypy --strict` clean.

Frontend: Vitest coverage of the Zod validation schemas and the login form's
client-side validation/submission behavior, `eslint` clean, `tsc --noEmit`
clean, `next build` succeeds.

## Security model (what exists today)

- Passwords are hashed with Argon2id; never stored or logged in plaintext.
- Sessions are httpOnly, `SameSite=Lax` cookies signed as JWTs; the frontend
  never reads or stores the token itself.
- RBAC (Owner/Admin/Security Engineer/Analyst/Viewer) is enforced
  **server-side only** — the frontend's UI is not a security boundary.
- A non-member accessing another organization's resources gets `404`, not
  `403`, so the organization's existence isn't confirmed to callers who have
  no legitimate reason to know it.
- Every auth and organization-membership action is written to an
  append-only, hash-chained audit log (`app/audit/service.py`), both as
  database rows and as a JSON-lines file.
- Structured error responses never leak stack traces or internal exception
  details to the client.

- The scope engine is the single outbound control point: exclusions are
  checked before allowlists, DNS is re-resolved per request, private and
  cloud-metadata ranges are refused, and redirects are never followed
  automatically. `GatedTransport` is the only place an HTTP client may be
  constructed, and a static test greps `app/` to keep it that way.
- Evidence is redacted before it is written, stored content-addressed with a
  hash-chained manifest, and served only to a member of the owning
  organization — there are no public report or evidence URLs. It is **not**
  encrypted at rest; see `docs/roadmap.md`.
- The AI assistant layer can draft and recommend. It cannot start a scan,
  grant authorization, or change a finding's real fields under any
  configuration.

What does **not** exist yet: rate limiting on auth endpoints and server-side
JWT revocation. See `docs/roadmap.md` for the complete list.

## Documentation

- [`docs/BUILD_SPEC.md`](docs/BUILD_SPEC.md) — the full, unified build
  specification (mission, safety policy, architecture, domain model, probe
  catalogue, risk scoring, reporting, phased plan, definition of done).
- [`docs/decisions/`](docs/decisions/) — architecture decision records.
- [`docs/cicd.md`](docs/cicd.md) — the `aegis-ai` CLI, API keys, and the CI
  security gate: its exit codes, and why it refuses to fail a build on an
  unstable finding.
- [`docs/roadmap.md`](docs/roadmap.md) — what's built, what's deferred, and
  why.

## License

[Apache-2.0](LICENSE) — see
[`docs/decisions/0004-licence.md`](docs/decisions/0004-licence.md) for the
rationale (a patent grant matters for security tooling).
