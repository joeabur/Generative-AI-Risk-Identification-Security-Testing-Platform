# Security policy

## Reporting a vulnerability

Report privately, not as a public issue. Use GitHub's **Report a vulnerability**
button on the Security tab, which opens a private advisory.

Include what you did, what happened, and what you expected. A proof of concept
against the demo lab in `demo-target/` is ideal — it is built to be attacked and
carries no real data.

We will acknowledge within 5 working days and aim to agree a disclosure timeline
with you. This is an open-source project without a paid security team; we will be
honest about timelines rather than optimistic.

## Scope

**In scope** — anything that breaks one of the platform's own guarantees:

- A path that reaches the network without passing the scope engine.
- Any way to make a request against a target with no valid authorization grant,
  or outside the rules of engagement.
- Reaching a blocked address — loopback, RFC1918, link-local, and especially the
  cloud metadata service — through a target, a notification channel, a code-host
  connection, an AI provider endpoint or a plugin.
- Cross-tenant access: reading or writing another organization's targets, runs,
  findings, evidence, channels or connections.
- A secret reaching disk, a log, an audit record, an API response or a report.
- Forging or silently altering an audit record or an evidence hash chain.
- Privilege escalation across the role ladder, including an API key acting above
  its scope cap.
- Anything letting the AI assistant execute a scan, grant authorization, or
  change a finding's non-draft fields.

**Out of scope:**

- Findings against the demo lab itself. It is deliberately vulnerable; that is
  its purpose, and `demo-target/README.md` lists the flaws by name.
- Missing hardening on a local development default that `.env.example` marks as
  local-only. `ENVIRONMENT=production` refuses to start with the development
  JWT secret; a report that it is insecure at `ENVIRONMENT=local` is not a
  finding.
- Denial of service through resource exhaustion against your own deployment.
- Vulnerabilities in third-party scanners we adapt (semgrep, bandit, pip-audit,
  checkov, gitleaks, trivy) — report those upstream. A flaw in *our adapter* —
  for example one that lets tool output inject a fabricated CVE into a finding —
  is in scope.

## What we will not do

We will not ship an exploit, a weaponized payload, or a jailbreak corpus, and we
will not accept one in a pull request. The AI probes detect using per-run random
markers rather than harmful content, on purpose (`docs/ai-security-testing.md`).

## Supported versions

Pre-1.0. Only the latest tag receives fixes.

## Our own controls

`docs/security-review.md` is a self-review of the platform's controls: what each
one is, how it was verified, and where the gaps are. `docs/threat-model.md`
states what this platform is trusted with and by whom.
