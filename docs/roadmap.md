# Roadmap

This file tracks what was deliberately deferred rather than silently stubbed,
per `docs/BUILD_SPEC.md` §0 rule 5 ("if you cannot implement something
properly within the phase, do not stub it silently — omit it, and record it
here with a reason").

## Phase 1 — Foundation (this build)

Delivered: repo layout, Docker Compose (postgres/redis/backend/worker/frontend),
FastAPI + Next.js skeletons, Argon2id auth (register/login/logout/me),
Organizations/Memberships/Roles with server-enforced RBAC, hash-chained
append-only audit log, Alembic migrations, Celery wired to Redis with a
placeholder task, and a real browser-driven register → create-organization
flow. Backend: 19/19 tests passing, ruff clean, mypy --strict clean, 92%
statement coverage. Frontend: ESLint, `tsc --noEmit`, Vitest (10/10), and
`next build` all clean.

Deferred out of Phase 1, with reasons:

- **`aegis-ai seed` / demo account seeding** — the Makefile intentionally has
  no `seed` target yet rather than one pointing at a module that doesn't
  exist. Lands with the demo lab (`docs/BUILD_SPEC.md` §19, Phase 12).
- **CLI (`aegis-ai`)** — Phase 10 per the merged phase plan
  (`docs/BUILD_SPEC.md` §26). The web app and REST API are the Phase 1–9
  surface; the CLI is a client of the same API, not a separate path.
- **GitHub Actions SHA-pinning** — `.github/workflows/ci.yml` pins actions to
  version tags (`@v4`), not commit SHAs. Full SHA-pinning
  (`docs/BUILD_SPEC.md` §23) is a Phase 11 supply-chain hardening item;
  fabricating an unverified SHA here would risk silently breaking CI, which
  is worse than a correctly-behaving version tag pending that pass.
- **Audit log table's append-only invariant is enforced by application code
  only** — no database-level `REVOKE UPDATE, DELETE` on the `audit_logs`
  table yet for the app's database role. Tracked for Phase 11 hardening
  alongside the rest of the security review.
- **Docker image builds were not verified end-to-end in this build
  environment** — `docker compose config` validates the compose file's
  syntax and service graph, and the Dockerfiles were reviewed by hand, but
  actually building `Dockerfile.backend`/`Dockerfile.worker`/
  `Dockerfile.frontend` requires pulling `python:3.12-slim` /
  `node:22-slim` / `postgres:16-alpine` / `redis:7-alpine` from Docker Hub,
  which this sandbox's network policy blocks (confirmed via the agent
  proxy's status endpoint: `connect_rejected — 403 to CONNECT — policy
  denial`, not a transient failure). The application itself **was**
  validated end-to-end for real: the backend was run under `uvicorn` against
  a live PostgreSQL + Redis, the frontend was built and run under `next
  start` against that backend, and a real browser-equivalent HTTP flow
  (register → session cookie → server-rendered dashboard → create
  organization → dashboard reflecting it → unauthenticated redirect) was
  driven with `curl` and passed. Building the container images themselves
  should be verified in an environment with Docker Hub access before first
  use (e.g. by the CI workflow, which runs in GitHub's own runners).
- **Rate limiting on auth endpoints** (`docs/BUILD_SPEC.md` §17.1: "login
  rate limiting") is not implemented in Phase 1. Noted here rather than
  silently skipped; add alongside the Phase 8 REST API hardening pass.
- **JWTs are not revocable server-side** — `auth.logout` only clears the
  session cookie; a bearer token obtained before logout remains valid until
  it expires (12 hours by default). This is a real limitation to carry into
  `docs/limitations.md` once that file exists (Phase 12/13 documentation
  pass), not something to silently fix with an unscoped session-blacklist
  abstraction in Phase 1.

## Phase 2 — Safety boundary (this build)

Delivered, test-first per `docs/BUILD_SPEC.md` §0 rule 4: the scope and
authorization engine (`app/core/scope/`) — the choke point every outbound
request must pass through. `RulesOfEngagement`/`Authorization`/`Budgets` as
pure, DB-independent dataclasses; `ScopeEngine.check()` (real pipeline,
consumes budget, halts the run on any hard violation) and
`ScopeEngine.explain()` (the dry-run/`scope explain` preview — identical
decision logic, never reserves budget or halts); `BudgetTracker` (atomic
request/token/cost/wall-clock reservation plus a concurrency semaphore);
`KillSwitch` (in-memory trip + sentinel-file check); `GatedTransport` (the
only place `httpx.AsyncClient`/`httpx.Client` may be constructed anywhere in
`app/`, enforced by a static test that greps the codebase and fails the
build otherwise — verified to actually catch a violation, not just pass
vacuously). `Target`/`Authorization`/`RulesOfEngagementRecord` persisted
models plus a REST API (target CRUD, RoE config, authorization grant
restricted to Owner/Admin per §17.2, and a `/scope/explain` dry-run
endpoint) — all RBAC-gated and cross-organization-isolated the same way
Phase 1's organizations API is.

Every case in the §6.3 mandated test matrix has its own test (not combined),
plus additional coverage beyond the minimum: IDN/punycode homographs,
userinfo-in-URL, DNS rebinding (proven by asserting the resolver was called
twice, not cached), cloud metadata IPs, RFC1918/loopback/link-local ranges,
explicit private-range allowlisting, path/method/header rules, all four
budget dimensions plus wall-clock and concurrency-under-load, blackout
windows, authorization absent/expired/not-yet-valid, RoE schema validation
failure, kill switch (in-memory and sentinel-file), and fail-closed behavior
on an internal exception — 84/84 backend tests passing, ruff clean,
mypy --strict clean, 99% statement coverage on `core/scope/` (target: ≥95%),
95% overall (target: ≥85%).

Deferred out of Phase 2, with reasons:

- **Redirect-target IP pinning (same-request DNS-rebinding TOCTOU)** — the
  engine re-resolves DNS fresh on every `check()` call, which catches a
  host's records changing *between* requests in a run (the DNS-rebinding
  test proves this). It does not pin the validated IP for the actual
  connection within a single request — `GatedTransport` lets `httpx`
  re-resolve DNS itself when it connects, which reopens a narrower,
  same-request TOCTOU window. Closing that requires connecting directly to
  the checked IP while preserving the original Host/SNI, a meaningfully
  larger piece of `httpx`/`httpcore` transport-level work. Tracked for the
  Phase 11 SSRF hardening pass rather than implemented partially or claimed
  as solved.
- **RPS (requests-per-second) pacing is not implemented** — `Budgets`
  carries `requests_per_second`, but only the request-count, token, cost,
  wall-clock, and concurrency dimensions are actually enforced in Phase 2.
  Actual rate-shaping (a token-bucket delay) plus a timing-based test would
  be inherently more flake-prone in CI than the other budget tests; add it
  deliberately in Phase 4 alongside the orchestrator's real request pacing,
  not as a rushed addition here.
- **Only one Authorization/RulesOfEngagement record per target** — granting
  a new authorization or setting a new RoE replaces the existing one
  wholesale rather than versioning a history. Simpler and safer than a
  half-built versioning model; revisit if the findings/evidence work in
  later phases needs to reference "the RoE that was active at scan time"
  for more than the most recent grant.
- **`/scope/explain` uses real system DNS in production** (`SystemDnsResolver`
  via a FastAPI dependency, overridden with a fake resolver only in tests)
  — this means a dry-run preview against a real target does a live DNS
  lookup, same as a real request would. That's intentional (an explain that
  used stale/cached data could mislead an operator about what would
  actually happen) but means `/scope/explain` is not fully side-effect-free
  at the network level, only budget/state-free.
- **No frontend UI for assets/scope yet** — Phase 2 is backend/API-only;
  targets, RoE, and authorization are managed via the REST API. The web UI
  for this (§18.3–18.6 in the spec) is deferred to land alongside Phase 3's
  adapter/discovery UI so it's built once against a more complete API
  surface rather than twice.
- **OpenAPI spec upload/parsing** — not part of Phase 2 despite appearing
  adjacent to "asset CRUD" in earlier phase-table drafts; it belongs with
  attack-surface discovery in Phase 3 (`docs/BUILD_SPEC.md` §26), which is
  where it's actually implemented.

## Phase 3 — Adapters & discovery (this build)

Delivered: the adapter layer (`app/core/targets/`) and OpenAPI attack-surface
discovery (`app/core/discovery/`).

- **Adapter protocols**, split into `ConversationalAdapter` (`send(turn)`)
  and `RestSurfaceAdapter` (`operations()` / `send_operation(...)`) over a
  shared `TargetAdapter` base. The spec (§8) defines a single chat-shaped
  protocol; that shape does not fit `http_openapi`, where the unit of work
  is "call operation X with parameters". Splitting it beat inventing a fake
  `Turn` for every REST call — recorded here as a deliberate deviation.
- **`chat_http`** (JSON request template + JSONPath extraction),
  **`openai_compatible`** (`/v1/chat/completions` and `/v1/responses`
  shapes), **`http_openapi`** (spec-driven REST). All send exclusively
  through `GatedTransport`, so the Phase 2 static check still proves no
  ungated HTTP path exists.
- **Provider-reported token usage feeds `BudgetTracker.reconcile()`**, so
  §6.2's "use reported usage when available, estimate otherwise" is real
  rather than aspirational — the estimate is replaced by the truth before
  the next budget check.
- **OpenAPI 3.x parser** treating uploads as hostile input: `yaml.safe_load`
  only, remote `$ref`s refused rather than fetched (an SSRF primitive aimed
  at the scanner host), cycle-safe and depth-capped local ref resolution,
  document-size and operation-count caps, malformed path entries skipped
  rather than aborting the whole import.
- **Surface API**: spec upload (extension/size/filename validation, stored
  in the database rather than the filesystem so path traversal is
  structurally impossible), endpoint listing, and per-endpoint enable/
  disable that survives a spec re-upload.

155/155 backend tests passing, ruff clean, mypy --strict clean, 94% overall
coverage (91% across the new `core/targets` + `core/discovery` modules;
`core/scope` still at 99%).

Deferred out of Phase 3, with reasons:

- **Real tokenizer** — `app/core/targets/tokens.py` is an explicit
  ~4-chars-per-token heuristic, not a tokenizer, and says so. It is only
  used for the pre-flight estimate that reported usage then replaces.
  Adding `tiktoken` (or equivalent) is a dependency decision worth making
  deliberately alongside the AI engine in Phase 6, not smuggled in here.
- **`graphql`, `mcp`, `websocket`, `cli_subprocess` adapters** — §8 lists
  seven adapters; Phase 3's acceptance criterion names three, and those
  three are what the API/AI engines in Phases 5–6 need. The remaining four
  land when there is an engine that actually exercises them, rather than
  shipping four untested integration surfaces now.
- **Live discovery (probing well-known spec paths on a target)** — surface
  discovery is currently spec-upload-driven only. Fetching
  `/openapi.json` from a live target is a scope-gated request like any
  other and is straightforward to add; it is deferred to Phase 4, where the
  orchestrator that would run it exists.
- **Request-body parameter schemas are captured as content types only** —
  the parser records *which* media types an operation accepts, not the full
  inlined body schema. Generating valid/invalid request bodies from those
  schemas is the input-validation probe's job (§10, Phase 5), which is
  where the schema walk belongs.
- **No frontend UI for surface review yet** — same reasoning as Phase 2's
  scope UI deferral: both land together against a settled API surface.

## Later phases

See `docs/BUILD_SPEC.md` §26 for the full phase plan (Phases 4–13: assessment
engine, API/AI security engines, findings & risk, evidence & reporting,
remediation & retest, CLI/CI gate, plugins, demo lab & hardening,
documentation & release).
