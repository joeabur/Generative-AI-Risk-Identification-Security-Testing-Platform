# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

## [0.1.0] — 2026-09-25

First release. A working, authorized-testing AI and API security platform with
an enforced safety boundary, measured findings, sealed evidence, and honest
reports.

### Safety boundary

- Scope engine as the single outbound control point, with a gated transport that
  is the only place in the codebase an HTTP client is constructed. A static test
  enforces it.
- Authorization grants as a first-class object — a named person, role, reference
  and validity window — digested onto every run and reproduced in every report.
  A run without one is refused.
- Rules of engagement: domains, IP ranges, paths, methods, forbidden headers,
  blackout windows, safe mode and budgets.
- DNS re-resolved at send time, so a rebind cannot move a request out of scope;
  redirects never followed, and a `Location` re-checked as a fresh target.
- Cloud metadata addresses refused unconditionally and not allowlistable.
- Redis-backed kill switch, honoured across processes.
- Append-only, hash-chained audit log mirrored from a file log.
- Scope-gated crawler and Nuclei/ZAP DAST adapters under safe mode (see
  `docs/limitations.md` for the one place DAST does not go through the
  gated transport).

### Account security

- Login and registration rate-limited on two dimensions (per-IP and
  per-identity), fail-open on Redis unavailability with Argon2id standing
  behind it either way.
- CSRF protection for every cookie-authenticated write, including a
  pre-session anonymous token (`docs/csrf.md`) so login and registration
  are covered too, not only requests made after one exists.
- Server-side JWT revocation: `/auth/logout` kills one token by its `jti`,
  `/auth/logout-all` kills every token issued before a durable Postgres
  cutoff. `GET /auth/sessions` lists what is currently active and
  `DELETE /auth/sessions/{id}` revokes one specific *other* session by
  name (`docs/revocation.md`).

### Engines

- **API security**: 18 probes covering authentication, transport, CORS, headers,
  debug endpoints, rate limiting, pagination, mass assignment (analysis mode),
  input validation, BOLA, function-level authorization and GraphQL.
- **AI security**: direct injection (six variants), sensitive disclosure, hidden
  context, insecure output handling, excessive agency and unbounded consumption
  — measured over trials against a control arm, with Wilson 95% intervals.
  Detection is marker-based; no harmful-content corpus ships.
- **AppSec**: Semgrep and Bandit (SAST), pip-audit (SCA), two secrets engines
  (working tree and git history), Checkov (IaC).
- **Supply chain**: end-of-life runtimes, dependency licence obligations,
  name-confusion and install-hook signals, known-malicious package
  identification against a vendored GHSA snapshot, and container package
  scanning.

### Findings, evidence and reports

- Ordinal risk model with generated severity rationale; stable fingerprints that
  never include response text or line numbers.
- Finding lifecycle with a restricted transition table, a remediation board, and
  a retest workflow reporting reproduced / not reproduced / **not tested**.
- Evidence redacted *before* it is written, content-addressed and hash-chained;
  verification re-walks the chain and re-hashes the files. Encryption at rest
  is opt-in (`AEGIS_EVIDENCE_ENCRYPTION_KEY`, AES-256-GCM) — unset, a bundle is
  protected by filesystem permissions and redaction alone, same as before this
  existed (`docs/configuration.md`).
- Reports in Markdown, HTML, PDF, JSON, SARIF 2.1.0 and CSV, in four audience
  templates, each naming the framework categories that were **not** tested.

### Dashboard

- A read-only, server-rendered dashboard (`/app`) — overview, findings, runs,
  workflows, targets — authenticated by the same session cookie as the API,
  scoped by the same membership check. Findings and runs both page past their
  first 50 rows. Every visible write action is a disabled control naming the
  API or CLI call that performs it, not a hidden button.

### CI/CD and integrations

- `aegis-ai` CLI over the same API and scope engine as the UI.
- Scoped API keys, capped at security engineer so a CI credential can never
  grant authorization.
- Security gate with documented exit codes (0 pass, 1 gate failed, 2 config
  error, 3 auth error, 4 scope violation).
- Outbound notifications: Slack, Microsoft Teams, a signed generic webhook and
  SMTP email, with retry, dead-letter and an audit event per attempt.
- Pull-request publishing as a GitHub check run with inline annotations, sharing
  the gate's verdict. It cannot push, merge or edit — enforced three ways.

### Extensibility

- Entry-point plugins with an operator allowlist pinned by distribution hash,
  `--no-plugins`, and a startup banner. **No sandbox is claimed.**
- AI intelligence layer with an autonomy ladder, a deterministic fake provider
  for CI, and no path to execution. The full suite passes with no provider
  configured.

### Demo lab

- Ten seeded flaws across a vulnerable AI app, a hostile content server and a
  collaborator endpoint. Runs on an internal network with no gateway and no
  published ports, and refuses to start if any of thirteen provider credential
  variables is present.

### Known limitations at 0.1.0

Stated rather than discovered later; the full list is in `docs/limitations.md`.

- DAST exists (a scope-gated crawler, Nuclei and ZAP under safe mode) but is
  not gated at the socket the way every other outbound path is — the two
  scanners open their own connections. No browser, no client-side testing.
- The dashboard is read-only by scope decision; every write is API or CLI
  only.
- `docker compose up --build` is written but **unverified** — image pulls were
  blocked in the build environment. The direct-run path is verified end to end.
- No RASP agent, by decision (Phase 18 is extension points only).
- `retest.completed` and `gate.failed` are defined notification events that
  nothing emits yet.
- SMTP is adjudicated by the scope engine but not carried by the gated
  transport.
- Plugins are not sandboxed; the allowlist is the control.
- Evidence encryption at rest is opt-in, not the default; unset, filesystem
  permissions and redaction are what protect a bundle.
- Rate limiting covers login and registration only — no general throttling
  on the rest of the platform's own API.
- Malicious-package matching is against a small, vendored snapshot of
  published GHSA malware advisories (50 entries), not a live feed — absence
  from that table means "not in this sample", never "confirmed clean".
- No signature verification for plugins, and no container image signing —
  images are scanned, none is published or signed.
- No admin visibility into another user's sessions; `GET /auth/sessions` and
  `DELETE /auth/sessions/{id}` are scoped to the caller's own account.

[Unreleased]: https://github.com/joeabur/Generative-AI-Risk-Identification-Security-Testing-Platform/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/joeabur/Generative-AI-Risk-Identification-Security-Testing-Platform/releases/tag/v0.1.0
