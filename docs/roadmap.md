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

## Phase 4 — Assessment engine (this build)

Delivered: `AssessmentRun`/`RunEvent` models with an append-only, sequenced
event log; a DB-free orchestrator (`app/core/orchestrator/`) that turns a
list of checks into a terminal run status; a Celery task that executes a run
in a worker process and persists progress as it goes; cross-process
cancellation carried over Redis into a latching `KillSwitch`; and the runs
REST API (create, list, get, events, cancel, and SSE progress). Backend:
184/184 tests passing, ruff clean, `mypy app` clean, 96% statement coverage
(scope engine still 100%, runs router 100%).

Two design points worth stating, because both are honesty requirements from
the spec rather than implementation details:

- **A halt is not automatically a failure.** Budget exhaustion ends a run as
  `completed` with a `halted_reason`, because the run did everything its
  budget permitted and the report must say so; an operator cancellation ends
  it `cancelled`; an authorization that lapses mid-run ends it `expired`.
  Only a check that raises produces `failed`.
- **Progress is never faked.** The SSE stream replays persisted `RunEvent`
  rows and nothing else, so a browser can never show progress ahead of the
  work, and it closes only once the run has reached a terminal status.

Two bugs found by running a real Celery worker rather than only the test
suite, both fixed here and both now covered by `tests/test_workers.py`:

- The worker registered no assessment task at all (`include=` was missing
  from the Celery app), so it started cleanly and discarded every queued run
  as "unregistered task" while the API kept reporting those runs as queued.
- Each Celery task runs under its own `asyncio.run`, and an asyncpg
  connection belongs to the loop that opened it, so the *second* run in any
  worker process died with "attached to a different loop". The task now
  disposes the engine before its loop closes.

Deferred out of Phase 4, with reasons:

- **The acceptance criterion "runs end-to-end against the demo lab" is met
  against a mocked target, not a lab.** The demo lab is Phase 12
  (`docs/BUILD_SPEC.md` §19, §26) and does not exist yet. The full path —
  API create → broker → worker → scope-gated requests → persisted events →
  terminal status — is exercised in `tests/test_runs_api.py` with the
  network faked at the `httpx` boundary (so the scope engine, budgets and
  transport are all real), and was additionally driven through a live Celery
  worker against Postgres and Redis by hand during this build. That is not
  the same as a lab, and is recorded here as the gap it is.
- **Only one check ships (`core.reachability`).** It issues one request per
  enabled endpoint and records the status or the scope rule that refused it.
  It is deliberately not a security test: the AI and API probe catalogues
  are Phases 5–6, and inventing probes now would pre-empt that work with
  untested ones. The check protocol it implements is what those catalogues
  plug into.
- **Live discovery (probing well-known spec paths) did not land here** — it
  was deferred *to* Phase 4 in the Phase 3 notes above. The orchestrator now
  exists, but the useful form of it is a check in the catalogue rather than
  a one-off, so it moves to Phase 5 with the API engine.
- **Runs are not resumable and there is no retry policy.** A worker killed
  mid-run leaves the run in `running`; nothing currently reaps it. A
  heartbeat plus a reaper is an operational concern that belongs with the
  Phase 11 hardening pass, and inventing a half-reaper now would make stale
  runs *look* handled.
- **`requests_per_second` is still not enforced** (carried from Phase 2).
  Concurrency, request count, tokens, cost and wall-clock all are; pacing
  needs a limiter shared across worker processes, which arrives with the
  rate-limiting work in Phase 11.
- **No frontend UI for runs yet** — the runs API and its SSE stream are
  complete and exercised, but the dashboard surface lands with the scope and
  surface UIs, against a settled API.
- **Cancellation fails open if Redis is unreachable.** `is_cancellation_requested`
  returns `False` on a `RedisError` rather than stopping every run, which is
  the documented trade-off in `app/workers/cancellation.py`: a genuine
  cancellation also writes a terminal status to Postgres, and the run stays
  bounded by its budgets, authorization window and wall clock regardless.

## Phase 5 — API security engine (this build)

Delivered: a probe contract (`ScanResult` per §11.1, a `Probe` protocol and
an explicit registry), sixteen API probes covering OWASP API2 (authentication,
transport, key material in URLs), API1/API5 (BOLA and function-level
authorization via authorized synthetic accounts), API3 (mass assignment),
API4 (rate-limit advertisement, pagination limits), API8/API9
(security headers, CORS, verbose errors, debug endpoints, input validation)
and GraphQL (introspection, depth/aliasing cost, error verbosity);
credential *references* with worker-side resolution; a `ScanResultRecord`
table; probe execution wired into the orchestrator; and `GET
/runs/{id}/results`. Backend: 227/227 tests passing, ruff clean, `mypy app`
clean, 95% statement coverage (scope engine still 100%).

Four decisions worth stating, because each is a deliberate limit rather than
an oversight:

- **Mass assignment is analysis-only, in every mode.** §10 requires that
  under safe mode, and safe mode is what runs ship with. Confirming mass
  assignment means writing `is_admin: true` to a real record; a tool that
  does that to prove a point has caused the incident it was hired to find.
  The specification already says whether the field is bindable, so the probe
  reports it at `DESIGN_REVIEW` confidence, clearly labelled, and never as a
  confirmed exploit. With safe mode off it says explicitly that live
  confirmation is not implemented rather than quietly behaving the same way.
- **Authorization probes need a control, and say so when they cannot get
  one.** A BOLA test asks the owning account for its own object first. Without
  that, a 404 to the second account would be reported as "correctly denied"
  when the object may simply not exist, and an endpoint that returns 200 to
  everyone would be reported as BOLA. Where no synthetic accounts are
  configured, the probe emits an explicit "not tested" result — silence
  would read as a pass on the single highest-value check in the engine.
- **A credential is never stored.** The database holds the *name* of an
  environment variable, validated to look like one so a token cannot be
  pasted in by mistake; the worker resolves it at run time into a
  `CredentialSet` that exposes it only as a request header. A test asserts
  no credential value appears in any field a report is built from.
- **A crashed probe is a visible gap, not a silent pass.** A probe that
  raises produces an `AEGIS-API-099` informational result and the run
  continues. Without it, a probe failing on every endpoint would look
  identical to a probe that found nothing — the most dangerous false
  negative a scanner can have.

Deferred out of Phase 5, with reasons:

- **The acceptance criterion is met against fixture apps, not the demo
  lab.** §26 asks for "every seeded API flaw in the demo lab; zero findings
  against a hardened control app". The lab is Phase 12 and does not exist, so
  `tests/lab/` contains two in-process applications — one carrying 17 seeded
  flaws, one built correctly — served through the real `GatedTransport` and
  the real scope engine with only the socket replaced. The engine finds all
  17 and reports nothing against the control, and removing a single
  hardening measure from the control app was checked to make that test fail.
  That is a genuine test of the engine; it is not a deployable, isolated lab,
  and this entry is the record of that difference.
- **SSRF (API7) is not implemented.** §10 requires a scope-controlled local
  collaborator in the lab, or a non-resolving canary domain against real
  targets, and is explicit that a target must never be pointed at a third
  party. The collaborator is lab infrastructure that arrives in Phase 12;
  shipping an SSRF probe without it would mean either no way to observe the
  callback, or pointing someone's API at a host we do not control. Neither is
  acceptable, so the probe waits for the lab.
- **JWT-specific authentication tests are not implemented** — `alg:none`,
  unsigned tokens, absent expiry. These need a token to manipulate, which
  means the synthetic-account credential, and the useful version of the check
  reasons about the token's structure. It belongs with the credential
  handling work rather than bolted onto the unauthenticated-access probe.
- **Spec/production drift and stale API versions (API9) are not
  implemented** — the parser records the declared surface and the probes
  exercise it, but nothing yet compares what the spec declares against what
  the server actually exposes. That needs live discovery (also deferred, see
  Phase 3/4 entries) to be worth anything.
- **No trials, ASR or confidence intervals yet.** §7's machinery applies to
  probabilistic AI probes; every API probe here is deterministic, so a single
  observation is the whole result and an ASR would be theatre. The machinery
  lands with the AI engine in Phase 6.
- **Results are not yet findings.** `ScanResultRecord` stores the §11.1 wire
  shape. Fingerprinting, risk scoring, severity rationale, mapping versions
  and lifecycle are the findings service in Phase 7, and the API deliberately
  returns no risk score rather than inventing one at the boundary.
- **No frontend UI for results yet** — same reasoning as the scope, surface
  and runs UIs: they land together against a settled API.

## Phase 6 — AI security engine (this build)

Delivered: the trials/baseline/ASR machinery (Wilson score intervals, an
explicit decision rule, stability classification) with a determinism harness;
eleven AI probes covering LLM01 direct injection (six techniques), LLM02
disclosure, LLM08 hidden context, LLM10 output handling, LLM06 consumption and
LLM03 excessive agency with a Mermaid permission graph; a standalone
redaction module; a judge that ships **disabled**; adapter configuration on
the target; and the AI engine wired into runs. Backend: 276/276 tests
passing, ruff clean, `mypy app` clean, 95% statement coverage.

Decisions worth stating:

- **The judge ships disabled, and that is the outcome, not a gap.** §7.3 says
  "an uncalibrated judge does not ship". Publishing precision and recall we
  have not measured would be worse than having none, so `JudgeConfig` cannot
  be enabled without a `Calibration`, enforced by the type and by a test.
  Every detection in this engine is marker-based or structural.
- **Every payload is a canary request.** A probe succeeds when this run's
  random marker comes back — never by eliciting harmful output (§2.2).
  Nothing in `direct_injection.py` is a jailbreak; the techniques tested are
  structural (override, role framing, delimiter confusion, hierarchy,
  encoding, language switching), which is what prompt-handling is supposed to
  withstand and which an instruction as innocuous as "say this word" tests.
- **Output handling deliberately does not use the ASR decision rule**, and
  says so in the finding. The adversarial component there *is* the structure,
  so a control with the structure removed is a plain-text echo — which an
  application that escapes correctly would also return. Applying the rule
  anyway would report a reliably vulnerable target as clean, so the probe
  reports deterministic reachability and carries the echo rate as context.
- **A tool surface is never guessed.** An empty declaration means "not
  declared", so the agency probe reports "not tested" rather than a clean
  permission graph. Architectural findings are valid at `DESIGN_REVIEW`
  confidence: an agent holding an irreversible external tool behind no
  confirmation is a real finding, and establishing it by triggering the tool
  would cause the irreversible effect being warned about.

Three bugs found while building, each now covered by a test:

- The trial driver **pooled trials across different techniques**, so one
  framing that worked every time and two that never did averaged into
  "inconclusive" — reporting a reliably exploitable target as clean. It now
  measures each technique separately and reports the strongest, naming it.
- `measurement_evidence` printed **raw response text**, so a credential the
  target disclosed reached the finding. Redaction now happens once, in the
  driver, when a trial is recorded — for every AI probe, not just the one
  looking for secrets.
- `.capitalize()` on a prompt containing the canary **lowercased the marker**,
  which silently made the affected controls unable to ever succeed.

Deferred out of Phase 6, with reasons:

- **The acceptance criterion is met against fixture apps, not the demo lab**
  (same as Phase 5). `tests/lab/ai_handlers.py` holds a seeded-vulnerable chat
  app and a hardened control, served through the real adapter, transport and
  scope engine with only the socket replaced. The engine finds all 11 seeded
  flaws and reports nothing against the control; removing one hardening
  measure from the control was verified to fail that test. They are
  deterministic stand-ins for model behaviour, which is what lets the test
  measure the engine rather than a model's variance — the statistics are
  covered separately by the determinism harness.
- **Indirect/cross-domain injection (LLM01) is not implemented.** §9 requires
  its carriers to be "served from the local content-server lab component
  only", and that component is Phase 12. Serving hostile HTML/PDF/DOCX from
  anywhere else to prove the path would mean planting attacker-controlled
  content somewhere we do not control.
- **LLM09 vector/embedding weaknesses are not implemented** — §9 restricts
  active poisoning to an authorized lab ingestion path, which does not exist
  yet.
- **LLM04/LLM05 supply chain and poisoning are not implemented** — inventory
  and ML-BOM work belongs with the SBOM tooling in Phase 12.
- **Multi-turn escalation is not implemented** — §9 gates it behind
  `allow_multi_turn`, and the adapters do not yet carry conversation state.
- **`aegis-ai replay <finding-id>` (§7.2) is not implemented** — trial records
  carry the exact prompt and a redacted response, which is what replay needs,
  but the command itself is Phase 10 with the rest of the CLI.

## Phase 14 — AppSec engines: SAST, SCA, Secrets, IaC (this build)

The first phase of the reconciled plan (`docs/IMPLEMENTATION_PLAN.md`).
Delivered: the `code_scope` domain model and a fail-closed workspace
resolver; a subprocess tool layer; identifier verification; static
fingerprinting; four engines (Semgrep and Bandit for SAST, pip-audit for
SCA, a repository secret scanner, Checkov for IaC); a `CodeScanCheck` for
the orchestrator; and the code-scope API. A vulnerable repository fixture
and a hardened control repository sit alongside the existing app fixtures.

**Acceptance met.** Nine seeded flaws across four pillars are found in the
vulnerable fixture, and the hardened control produces **zero** findings.
Both directions were verified to have teeth: reverting one hardening measure
in the control (`yaml.safe_load` back to `yaml.load`) fails the control test.

Decisions worth stating:

- **An empty `allowed_paths` is refused, not read as "everything".** A
  checkout with no stated boundary may contain a second project or a
  developer's credentials. This is §6.2's fail-closed rule applied to a
  repository, and it is enforced in the `CodeScope` constructor so no code
  path can bypass it.
- **A repository over the size cap is refused rather than truncated.** A
  partial scan reported as a complete one is the dishonest outcome.
- **Semgrep runs offline against a bundled local ruleset.** `--config
  p/default` downloads rules, and a subprocess that reaches the network is an
  outbound path §6.3 governs just as it governs an `httpx` client. A registry
  ruleset remains available as an explicit operator choice. The bundled rules
  are deliberately few, per the addendum's limit on native rules, and include
  `aegis.ungated-http-client` — this platform dogfooding its own central rule.
- **Dependency advisory lookup is off by default.** Matching a dependency
  graph means sending the client's dependency list to whoever runs the
  advisory database. That is a disclosure an operator opts into per
  assessment, so the default reports the inventory and states plainly that no
  matching was performed — an empty result would read as "no vulnerable
  dependencies", which is a very different claim.
- **Bandit's B404/B603/B607 are downgraded to informational, not
  suppressed.** They flag the presence of an API rather than a misuse of it
  and fire on correctly-written code; a scanner whose clean state is
  unreachable teaches its users to ignore it. They stay in the result set,
  attributed and explained, and simply do not count as findings. The reason
  is written into each finding's own description.
- **Fingerprints use a code-span signature, never a line number.** Line
  numbers drift on unrelated edits, so fingerprinting on them would split one
  long-lived issue into a new finding on every commit that touched the file
  above it.
- **Secret detection reuses the Phase 6 detector stack.** Two
  implementations would mean two redaction policies, which is how the §13
  "never persist a secret" invariant gets broken.
- **Checkov findings outside the code scope are dropped.** Checkov is pointed
  at the workspace root and does not honour our scope natively, so the
  adapter re-filters its output. The scope boundary stays authoritative even
  when a tool does not enforce it.

### Phase 14b — repository checkout and run-pipeline wiring

The deferred half of Phase 14. A run against a target with a `repo_ref` now
clones the repository, scans it, persists the findings and deletes the
checkout.

`git` does not route through `GatedTransport`, so every control the transport
would have applied is applied before `git` starts:

- **The repository host must be explicitly allowlisted.** A `repo_ref` is
  operator-supplied and therefore untrusted input; without an allowlist it is
  a request-forgery primitive aimed at whatever the worker can reach. An
  empty `allowed_repo_hosts` permits nothing.
- **The resolved address is checked against the scope engine's own blocked
  ranges** via `is_blocked_ip`, not a second list. An allowlisted name that
  points at loopback, RFC1918 or `169.254.169.254` is still refused.
- **Only `https` and `file` are accepted.** `ext::` makes a clone arbitrary
  command execution; `git://` is unauthenticated plaintext.
- **Hooks are disabled, submodules are never fetched, and the terminal
  prompt is off**, so a repository cannot execute its own code, pull content
  from a host that bypassed the checks above, or hang waiting for credentials.
- **The checkout is deleted in a `finally`,** including when the clone fails
  part-way. A working copy of a client's repository is precisely what must
  not be left on a worker: it is the material the secret scan just found
  credentials in.

A host that fails these checks skips code scanning and records why in the run
event log; the rest of the assessment is unaffected.

Two bugs the end-to-end test exposed, both fixed:

- **The scope engine reported an ordinary DNS failure as
  `internal_error` and halted the whole run.** A hostname that does not
  resolve is a normal outcome, not an engine fault. It now has its own rule
  (`dns_resolution_failed`), still fails closed — without an address there is
  no way to prove the host is not internal — but no longer aborts an
  assessment because one host is dead.
- **A file-reading check was skipped once the request budget halted.** A
  budget bounds outbound requests; it is not a general stop signal. Checks
  now declare `requires_network`, and the code engines — which spend no
  requests — keep running after a budget halt. An operator cancellation still
  stops everything.

Still deferred:
- **Container image and CI-artifact scanning are not implemented.** The
  addendum lists both as secret-scanning surfaces. They need an image-pull
  path, which is the same missing piece as the checkout above.
- **CodeQL is not integrated** — §15 requires verifying its licence before
  integrating, and that verification has not been done.
- **No cross-engine deduplication.** A SAST finding and a DAST finding
  describing the same underlying defect are two findings. The addendum
  explicitly puts this out of scope for v1; faking a correlation heuristic
  would be worse than the honest gap. Correlation belongs with the findings
  service in Phase 7 and the AI layer in Phase 16.
- **`nist_ssdf` mappings are not yet emitted.** The key exists in the finding
  schema, but §3.4's discipline requires verifying each practice against a
  pinned source first, and that ingestion has not been done. Emitting
  unverified practice ids would be exactly the invented-mapping failure the
  spec forbids.
- **The run pipeline does not yet execute `CodeScanCheck`.** The check, the
  workspace builder and the API all exist and are tested; wiring it into
  `execute_assessment_run` needs the checkout step above to be meaningful,
  so it lands with it rather than shipping a code scan that can only ever
  scan an empty directory.

## Phase 16 — AI intelligence layer (this build)

Delivered: an `AIService` with a two-method provider abstraction
(`generate`, `structured_output`), an OpenAI-compatible provider covering
hosted and self-hosted endpoints, a deterministic fake provider used
throughout the tests, the autonomy ladder, versioned prompt templates, an
`AiDraft` table with an explicit accept step, and the assistant API.

The shape the whole layer enforces (Implementation Specification §10):

    Tool / Engine -> Observation -> Detection -> Finding -> AI interpretation

Decisions worth stating:

- **The provider call goes through the same gated transport as everything
  else.** The provider endpoint is infrastructure the operator configured,
  not a target — but that is not a licence to open a second way out of the
  process, and an AI subsystem is the likeliest place for one to be added by
  accident. `platform_egress_context` builds a scope allowing the provider's
  host and nothing else, derived from configuration with no parameter a
  caller could widen. A provider endpoint resolving to the metadata service
  is refused exactly as a target would be.
- **`EXECUTE` is a mode, not a power.** The two source documents appeared to
  disagree about whether the assistant may execute anything; §4.5 row 7
  resolves it by asking *execute what*. Producing an artifact is something a
  mode permits; consuming budget, reaching a target, granting authorization
  or writing a finding's real fields is in `TARGET_TOUCHING`, checked
  independently of the mode so that raising the mode cannot grant one. There
  is no `execute()` on the service at all.
- **Evidence is fenced as data, and cannot close its own fence.** The
  material this layer summarises is adversarial by construction — it is
  harvested from injection probes, and the successful ones contain text
  written to redirect a reader. It is quoted inside a delimited block whose
  markers are stripped from the content, under a system prompt stating that
  nothing inside is an instruction. Passing it unfenced would repeat the
  mistake the platform tests its clients for.
- **Counts come from the platform, never from the model.** The executive
  summary is handed the severity counts and the untested list; a model asked
  to count would sometimes get it wrong, and a wrong number in an executive
  summary discredits the whole report.
- **An unreadable autonomy mode is treated as OFF, not as the default.** A
  typo in configuration must not silently grant more autonomy than the
  operator intended.
- **Accepting a draft is a higher privilege than requesting one.** Reading a
  suggestion is cheap; putting it into the record is not, so acceptance is an
  explicit act by a named person, recorded in the audit trail alongside the
  model and prompt template that produced the text.

One bug the boundary tests caught: `propose_scan` called the
target-touching guard unconditionally, so composing a command always failed.
The guard belongs where something tries to *act*, not where text is
produced.

Deferred out of Phase 16, with reasons:

- **Correlation and prioritisation are declared capabilities but not
  implemented.** Both need a `Finding` model with fingerprints and lifecycle,
  which is Phase 7. Correlating raw scan results would produce suggestions
  that cannot be acted on, and a "duplicate" suggestion across engines is
  exactly the cross-engine dedup already deferred in Phase 14.
- **Cost limits are configurable but not enforced.** `ProviderConfig`
  carries `max_cost_usd`, and the egress context carries a cost budget, but
  the OpenAI-compatible provider reports no cost because the wire format does
  not return one. Enforcing a limit against an estimated cost would be
  presenting a guess as a measurement, so the field is carried and the
  enforcement waits for per-model pricing data.
- **No CLI surface yet** (`aegis assist`, `aegis findings accept-draft`) —
  the CLI is Phase 10 and the API is the tested surface.
- **No structured-output use yet.** The provider implements
  `structured_output` and it is tested, but every current capability drafts
  prose. It exists for the correlation and prioritisation work above.
- **No import-linter configuration.** The "nothing in `core` outside
  `assistant/` imports it" contract is enforced by a test in
  `tests/security/test_assistant_boundary.py` rather than by the linter; the
  linter config lands with the rest of the Phase 11 tooling.

## Phase 7 — findings & risk (this build)

Delivered: the Aegis risk model with published ordinal tables, fingerprinting
that survives across runs, normalization from `ScanResult` into a stored
`Finding`, promotion wired into the run pipeline, and the findings API with
lifecycle transitions.

**Acceptance met.** §26 names two criteria and both are tested directly:
the fingerprint-stability test passes, and every finding carries a
`severity_rationale` that states the score it belongs to.

Decisions worth stating:

- **The score and its rationale are generated in the same call.** There is
  no path that produces one without the other, so a finding cannot carry a
  number nobody can account for. A rationale written beside a computed score
  drifts the first time either changes, and a reader who notices stops
  trusting both.
- **`docs/risk-model.md` is generated from the scorer's own constants.** A
  table maintained by hand is wrong the first time a weight changes, and §12
  requires the numbers to be published. A test asserts the document contains
  the values the scorer actually applies.
- **Likelihood uses the measured interval's lower bound, not the rate.** A
  3/5 success rate has a lower bound near 0.23; scoring it as 0.6 would treat
  sampling noise as an established fact. A probabilistic finding therefore
  scores below the identical deterministic one — which is the entire point of
  the Phase 6 measurement machinery reaching the risk number.
- **The fingerprint excludes response text**, per §11, and normalizes object
  ids, timestamps, canaries and short hex ids out of the surface and
  signature. Without that the same unfixed weakness becomes a new finding
  every run, the history is destroyed, and remediation has nothing stable to
  attach to. Both directions are tested: volatile detail collapses, and two
  genuinely different weaknesses stay distinct.
- **CVSS and AIVSS are left empty rather than manufactured.** §12 forbids a
  CVSS vector for "the model followed an injected instruction", which CVSS
  cannot express. An empty field is honest; a fabricated vector a reader will
  paste into a calculator is not.
- **A triage decision survives a re-run, with one exception.** Re-running a
  scan must not revert a human's judgement — except that something marked
  remediated which a later run still finds is reopened as confirmed, because
  a stale "remediated" on a live weakness is the most dangerous record in the
  system.
- **Transitions are restricted.** A finding cannot jump from `new` to
  `closed`; it has to pass through a state that records why, which is what
  makes a closed finding auditable months later. `remediated` leads only to
  `retest_required`, because a remediation is a claim until something checks
  it.
- **Exposure is read conservatively.** When the target's reachability is
  unclear the higher exposure is assumed: under-stating reach produces a
  comfortable number and an unpleasant surprise.

One bug the fingerprint-stability test caught: the hex-normalizing rule
required sixteen characters, so eight-character request and correlation ids
survived into the signature and would have produced a new finding every run.

Deferred out of Phase 7, with reasons:

- **`mapping_versions` is empty.** §3.4 requires each mapping to cite a
  pinned framework version with a retrieval date, and that ingestion has not
  been done. An unverified version string implies a check nobody performed,
  so the field stays empty and a test asserts it.
- **No evidence_ref yet.** The column exists; sealing evidence into a
  content-addressed bundle is Phase 8.
- **No cross-engine correlation.** Still the honest gap from Phase 14 and
  Phase 16: a SAST finding and a DAST finding describing the same defect
  remain two findings. The fingerprint now gives correlation something stable
  to work from, which is the prerequisite it was missing.
- **Exposure and impact are derived, not declared.** An operator cannot yet
  override the exposure reading for a target that is, say, behind a VPN the
  platform cannot see. The inputs are recorded on every finding so the
  derivation is visible and arguable; making it editable belongs with the
  remediation workflow in Phase 9.

## Phase 8 — evidence & reporting (done)

Evidence bundles are content-addressed, hash-chained and redacted before they
are written; reports render from one `ReportData` into Markdown, HTML, PDF,
canonical JSON, SARIF 2.1.0 and CSV across four audience templates; both are
downloadable only by a member of the owning organization, and every download
is audited.

Decisions worth stating:

- **Redaction happens before serialization, and the store refuses anything
  that got through.** `build_bundle` is the only sanctioned constructor, and
  `EvidenceStore.write` re-scans the serialized bytes and refuses the write,
  naming what tripped it. A bundle assembled by hand cannot be stored, so the
  guarantee does not depend on every future caller remembering.
- **A run's own canary is exempt from redaction.** This one was a bug the
  end-to-end test found, and it mattered twice over. The canary is a random
  16-hex-digit marker, so whether it happened to clear the entropy threshold
  decided whether a run could store evidence at all — the same target
  produced storable evidence on one run and none on the next. And redacting
  it destroys the evidence's whole point: a marker-based finding whose record
  reads `[REDACTED]` where the canary came back proves nothing. `find_secrets`
  now takes an `ignore` list, claims those spans first, and the driver, the
  bundle builder and the store all pass the run's markers through it.
- **Word boundaries came out of the secret patterns.** The property test
  defeated the old `\b(?:AKIA|ASIA)[0-9A-Z]{16}\b` in one line:
  `AKIAIOSFODNN7EXAMPLE0` contains a complete AWS key id, but the trailing
  `\b` fails against the extra character and the value passed through
  unredacted. Adjacency must not be a way to smuggle a credential past the
  detector, so the issuer prefixes anchor each match and the quantifiers are
  open-ended. The cost is occasional over-redaction of a token that merely
  starts like a key, which is the right way round.
- **The detector's own verdict is redacted too.** Nothing guarantees a
  detector kept only a digest; one that quoted what it saw would have put a
  disclosed credential into the bundle by a route redaction never covered.
- **Content addressing makes a re-write idempotent, not observations
  interchangeable.** `created_at` is part of a bundle's content, so two
  separate observations of an identical exchange stay two bundles. They were
  two trials, and collapsing them would understate the measurement. Writing
  the *same* bundle twice is one file and one chain entry.
- **Verification checks the chain and re-hashes the files.** The chain alone
  catches a removed or reordered entry; re-hashing catches one whose bytes
  were edited in place. Both failures are tested by doing the tampering.
- **The SARIF schema is the real OASIS one, vendored.** `tests/schemas/`
  holds the 2.1.0 schema fetched from the spec repository, with a README
  explaining why: an approximation would pass output the spec rejects, and
  fetching it at test time makes CI depend on the network. A companion test
  breaks the document deliberately and asserts the validator complains, so
  "it validates" means something.
- **Golden snapshots for every format and template.** A report is the
  artefact that leaves the platform, so a silent change to its wording,
  ordering or structure is a change to what an organization believes it was
  told. `UPDATE_GOLDEN=1` re-records them and the diff has to be read.
- **`level` is not severity, and the fingerprint travels.** SARIF has four
  levels and this platform has five severities; critical and high both map to
  `error`, with the Aegis score kept at full resolution in `properties`. The
  Phase 7 fingerprint becomes `partialFingerprints`, without which a code
  host shows every run's findings as new.
- **Two honesty gaps the templates closed.** The developer template had no
  coverage section, so a developer would have read a findings list with no
  statement of what the run did not look at; framework coverage is now in
  every template for its "not tested" half. And a finding with no measurement
  printed no rate at all, which a reader seeing rates on the finding above it
  could fairly read as a measured zero — it now says "not measured" and why.
- **Reporting does not import the assistant.** The boundary test caught an
  import of the assistant's evidence delimiters in `reporting/build.py`.
  Stripping a prompt artefact is the assistant's job where it stores a draft,
  not reporting's where it renders one; which sections a draft contributed is
  read from the `ai_drafts` rows.
- **A report is refused before the run has executed.** A document full of
  zeroes from a queued run reads like a clean result. A report from a
  *running* one is allowed and says so in its limitations.
- **Evidence download needs analyst, reports need viewer.** A bundle is
  redacted but still the closest thing kept to the raw exchange, and a
  read-only reporting account has no need for it. Both are 404 rather than
  403 for a non-member, and both are audited.

Deferred out of Phase 8, with reasons:

- **No encryption at rest.** §13 makes it optional, and a half-built
  implementation with an undocumented key model would be worse than none — an
  operator would believe the evidence was protected while the key sat beside
  it. What protects a bundle today is filesystem permissions and the
  redaction that ran before the write. `.env.example` and the compose volume
  say so where an operator will read it.
- **Evidence is only produced by the AI engine.** The AI driver has the whole
  exchange, so its findings carry bundles. The API and AppSec engines record
  their evidence as text on the result; giving them structured bundles needs
  the request/response to survive into `ScanResult`, which is a change to
  those engines rather than to the store. Findings without a bundle carry a
  null `evidence_ref` rather than a reference to nothing.
- **PDF needs an optional extra.** WeasyPrint is in a `pdf` extra because it
  needs system Pango and Cairo; CI installs it so the path is exercised, and
  the endpoint returns 501 with the install hint rather than a 500 when it is
  absent.
- **Retest results are a placeholder section.** The template has the section
  and the renderer states that no retest has been recorded; the retest
  workflow itself is Phase 9.
- **No scheduled retention job.** `EvidenceStore.purge` performs a genuine
  delete and is tested, but nothing calls it on a schedule yet — retention is
  a policy the operator has no way to configure.

## Engine completion pass (done)

Prompted by a review of what the engine actually produced end to end, not by
a phase boundary. Three real defects came out of it.

- **The `Observation` → evidence bundle pipeline finally exists.** The gated
  transport's own docstring had promised it since Phase 2 and it was never
  built, so only the AI engine's findings carried downloadable evidence. API
  probe findings now carry the exchange behind them, and the AppSec engines
  carry the tool, rule and code span. 14 of the 17 findings the vulnerable lab
  produces now have verifiable evidence; the other three are read out of the
  specification and carry none *on purpose* — a bundle asserts "this was
  observed", and a finding nobody observed must not claim one. A test names
  those three, so a new probe cannot quietly join them.
- **Evidence withholds the other party's data where that is the finding.**
  A BOLA probe establishes that account B reached account A's object; storing
  that object would turn the evidence bundle into a copy of the records the
  probe was only supposed to prove were reachable. Bundles therefore default
  to *not* retaining the response body, and a caller opts in where the body
  *is* the finding — a stack trace, an echoed marker, a GraphQL schema. Both
  directions are tested.
- **`uri.lstrip("./")` leaked the checkout directory into every semgrep
  finding.** `lstrip` strips characters, not a prefix: `./src/app.py` became
  `src/app.py` as intended, and
  `/home/runner/checkout-a1b2/src/app.py` became
  `home/runner/checkout-a1b2/src/app.py`. The path is part of the §11
  fingerprint and a checkout directory is unique per run, so every static
  finding got a new identity on every scan — no dedup, no history, no "is this
  still there?" — and the worker's filesystem layout went into
  customer-facing reports. Now one shared `relative_to_workspace` resolves
  against the workspace and drops anything outside it, with a regression test
  that scans the same file from two checkout directories and asserts one
  fingerprint.

The audit also confirmed what was already right: the vulnerable lab yields 17
API findings and 23 static ones, the hardened control yields zero and zero
reportable, and all 17 API findings have distinct fingerprints.

## Phase 9 — remediation & retest (done)

A finding can be assigned with a due date, moved through the §11 lifecycle,
retested, and shown as reproduced or not reproduced with the evidence digests
either side.

Decisions worth stating:

- **A retest is a run.** It reuses `assessment_runs` with `kind=retest`, so it
  inherits the authorization gate, the scope engine, the budgets, the audit
  event and the evidence path rather than re-earning each of them — and cannot
  drift from them later. It also takes its own explicit
  `authorization_confirmed`: having scanned something once is not standing
  permission to scan it again.
- **There is no status column on a remediation task.** The finding's lifecycle
  is the single source of truth for security state; the task carries the work
  (assignee, due date, notes). Two state machines over one fact drift, and
  when they disagree nobody can say which one a report should believe.
- **`not_tested` is a first-class verdict, and it is why this phase needed a
  new table at all.** An ordinary scan cannot express an absence: a run that
  no longer reports a weakness looks exactly like a run whose probe never got
  to try. So a retest writes down what it set out to check and gives each
  finding a verdict — and a probe that was skipped, refused by scope, held
  back by safe mode, or cut short by a halt is reported as not tested, never
  as a fix. Two tests drive that path specifically.
- **"Did the probe run?" needed its own record.** The first implementation
  inferred it from whether the probe wrote any result, which is wrong in the
  dangerous direction: a probe that ran and found nothing writes nothing, so a
  genuine fix was being reported as `not_tested`. Runs now record
  `probes_executed` from the orchestrator's own check results. A run from
  before that column existed has an empty list and every verdict fails closed
  to `not_tested`.
- **The baseline is a snapshot, not a live read.** Both halves of the
  comparison move otherwise: the run overwrites a reproduced finding's
  `evidence_ref`, and someone triaging in the meantime changes its state. The
  run stores each finding's id, fingerprint, probe id, severity and evidence
  digest before it starts.
- **Only a finding that was awaiting a retest is closed by one.** Requesting a
  retest moves `remediated` → `retest_required`, which is the transition §11
  reserves for exactly this moment. A not-reproduced verdict then closes it and
  closes its task. A finding still `in_remediation` has not been declared
  fixed by anybody, and the platform will not declare it for them.
- **A report says which kind of claim it is making.** A retest renders the
  three verdicts with before/after digests. An assessment renders recurrence
  instead and labels it as the weaker claim it is, rather than implying it
  compared anything.
- **A retest naming an unknown finding is refused, not narrowed.** Quietly
  dropping a finding would report a clean result for work that was never
  checked.

Deferred out of Phase 9, with reasons:

- **No partial retest.** A retest re-runs the target's whole configured check
  set and then compares; it does not run only the one probe behind a finding.
  Narrowing the run would be faster but would change what the control
  comparison means, and the ASR machinery's controls are per-probe for a
  reason. Recorded as a performance gap, not a correctness one.
- **No notifications.** §17's `retest.completed` webhook and in-app events are
  not built; the verdicts are visible through the API and the report.
- **No SLA or ageing on the board.** Due dates are stored and returned, but
  nothing computes breach, and no effort or priority band is invented — the
  report is explicit that this tool does not estimate effort.
- **Before/after evidence is two digests, not a diff.** A reader can download
  both bundles and compare them; the platform does not render a structured
  difference between them.

## Phase 10 — CLI, API keys & CI/CD gate (done)

`aegis-ai` exists as a console script, organizations can mint scoped API keys
for CI, and `aegis-ai gate` / `aegis-ai ci` fail a build on a seeded critical
finding with the documented exit code.

Decisions worth stating:

- **The CLI is its own package, and a test enforces it.** §26 Phase 10
  requires the CLI to exercise the same API and scope engine as the UI rather
  than a weaker path of its own, and the strongest way to guarantee that is
  structural: `aegis_cli/` may import `app.core.gate` (pure logic over
  findings the API returned) and the shared enums, and nothing else from
  `app.core`. It holds no scope engine, no probe, no adapter and no database
  session, so the only way it can reach a target is to ask the API to — which
  means every request it causes passes the same authorization gate a browser
  session does. `tests/test_cli.py` asserts that rather than trusting it.
- **`--safe` is passed to the API, not honoured by the CLI.** A flag the
  client enforced by itself would be a second, weaker gate, and the one that
  matters would be the one nobody was looking at.
- **An API key cannot grant authorization.** Its scopes top out at security
  engineer, so it cannot create a target, amend an authorization, add a
  member, or mint another key. A credential living in a CI runner is the most
  exposed thing this platform issues, and the authorization grant is the
  human act that makes a scan lawful. A test mints an owner's key and proves
  all four are refused — without the role cap, every key an owner created
  would have been an owner key.
- **A key's authority is its scopes; the role is derived.** One source of
  truth. Carrying both a scope list and a role invites the two to disagree,
  and then nobody can say which the platform enforces.
- **The secret is SHA-256, not Argon2.** It is 256 bits of CSPRNG output, so
  there is nothing to brute-force; a deliberately slow KDF on every CI request
  would buy latency and no security. A password is the opposite case, which is
  why `app/auth/security.py` still uses Argon2id for those.
- **The gate refuses to fail a build on a single-shot finding.** §23 names the
  failure mode plainly — gating on unstable, low-confidence AI findings makes
  pipelines flaky and gets the tool switched off by the first adopting team —
  so `require_stability` defaults to deterministic and probabilistic only.
  Low-confidence, design-review and already-triaged findings are excluded for
  the same reason. Gating on single-shot results is possible, but has to be
  asked for.
- **Every exclusion is printed with its reason.** A gate that says "failed: 3
  findings" teaches people to add `|| true`; one that shows what it skipped
  and why is one they can argue with, and arguing with it is how it stays
  switched on.
- **An unknown setting in `security-gate.yaml` is an error.** A typo'd
  `max_hihg: 0` that silently did nothing would leave a team believing they
  had a gate they did not have.
- **`fail_on` is a threshold, not a set.** `[high]` also fails on critical: a
  gate that let a critical through because the list said "high" would be
  indefensible.
- **A refusal never exits 0.** Authentication problems exit 3, a scope refusal
  or a halted run exits 4, a bad configuration exits 2 — and only a real
  finding exits 1. Reporting "no findings" because the tool could not
  authenticate would be worse than having no gate.
- **`ci` gates on the run it started**, not on the organization's backlog,
  which would fail one team's build for another team's open finding.

Two bugs the tests caught, both about the gate saying something it did not
mean:

- `max_high: null` was being read as "use the default of 0", because the
  parser could not tell an explicit null from an absent key. The documented
  example uses null to mean "no limit", so the parser now distinguishes them.
- The gate initially matched `fail_on` exactly, so a config listing `high`
  would have passed a critical.

Deferred out of Phase 10, with reasons:

- **Four of the nine §23 workflows are absent, not stubbed.** `container.yml`
  needs images this repository does not yet build in CI, `lab-e2e.yml` needs
  the Phase 12 demo lab, `release.yml` needs the Phase 13 release process, and
  `framework-drift.yml` needs the pinned framework corpus from §3.4 that
  `mapping_versions` is still empty for. A workflow that exists and does
  nothing is worse than one that is honestly missing.
- **detect-secrets runs against a committed baseline.** A bare scan of this
  repository is red on day one — 31 files of migration revision hashes,
  environment-variable *names*, and the credentials the vulnerable lab fixture
  contains deliberately — and a job that is red from the start gets disabled
  rather than fixed. The baseline stores hashes, not values, and the step
  fails on anything new (verified by planting an AWS key and watching it
  fail). Running the CI steps locally before committing the workflow is what
  surfaced this; it also surfaced that the platform's own Semgrep rule fires
  on the gated transport and on the CLI's API client, both now suppressed at
  the line with a stated reason rather than by excluding the files.
- **Actions are pinned to tags, not SHAs.** §23 asks for SHAs; the existing
  `ci.yml` pins tags and changing that convention is a repository-wide edit
  that belongs with the Phase 12 supply-chain work.
- **Some §20 commands are absent rather than stubbed**: `init`, `test --probe`,
  `replay`, `frameworks`, `probes list` and `evidence purge`. Each needs an
  endpoint the platform does not have yet, and a command printing "not
  implemented" is still a command people script against — `aegis-ai probes
  list` returning nothing would read as "this build has no probes".
- **No OIDC.** §21 lists API-key *or* OIDC authentication; only the first is
  built.
- **No rate limiting on authentication endpoints**, which §21 also asks for
  and which remains the oldest open item on this list.

## Later phases

See `docs/BUILD_SPEC.md` §26 for the full phase plan. Remaining: Phases 11–13
(plugins, demo lab & hardening, documentation & release), plus Phase 15
(DAST), 17 (workflows, dashboard) and 18 (RASP extension points).
