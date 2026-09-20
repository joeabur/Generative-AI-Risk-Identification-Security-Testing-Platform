# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

## [0.1.0] — 2026-09-20

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
  name-confusion and install-hook signals, and container package scanning.

### Findings, evidence and reports

- Ordinal risk model with generated severity rationale; stable fingerprints that
  never include response text or line numbers.
- Finding lifecycle with a restricted transition table, a remediation board, and
  a retest workflow reporting reproduced / not reproduced / **not tested**.
- Evidence redacted *before* it is written, content-addressed and hash-chained;
  verification re-walks the chain and re-hashes the files.
- Reports in Markdown, HTML, PDF, JSON, SARIF 2.1.0 and CSV, in four audience
  templates, each naming the framework categories that were **not** tested.

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

- No DAST or crawler (Phase 15); no browser, no client-side testing.
- The web UI covers authentication only; everything else is API or CLI
  (Phase 17).
- `docker compose up --build` is written but **unverified** — image pulls were
  blocked in the build environment. The direct-run path is verified end to end.
- No RASP agent, by decision (Phase 18 is extension points only).
- `retest.completed` and `gate.failed` are defined notification events that
  nothing emits yet.
- SMTP is adjudicated by the scope engine but not carried by the gated
  transport.
- Plugins are not sandboxed; the allowlist is the control.
- Evidence is unencrypted at rest; no rate limiting on the platform's own API.

[Unreleased]: https://github.com/joeabur/Generative-AI-Risk-Identification-Security-Testing-Platform/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/joeabur/Generative-AI-Risk-Identification-Security-Testing-Platform/releases/tag/v0.1.0
