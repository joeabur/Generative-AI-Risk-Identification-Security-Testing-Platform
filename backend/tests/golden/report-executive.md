# Security assessment — Support assistant "beta" & API

**Template:** executive  
**Generated:** 2026-03-04T09:30:00+00:00  
**Tool:** Aegis AI Security 0.1.0  
**Run:** `22222222-2222-2222-2222-222222222222`

## Executive summary

3 finding(s) were identified against Support assistant "beta" & API (llm_app, staging).

- Critical: 1
- High: 1
- Medium: 1
- Low: 0

1 area(s) were **not tested** in this assessment; see Framework coverage for the list and the reasons.

## Authorization & scope

- Authorized by: A. Okafor (CISO)
- Reference: AUTH-2026-014
- Valid: 2026-03-01T00:00:00+00:00 to 2026-03-31T00:00:00+00:00
- Authorization digest: `sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`
- Rules of Engagement digest: `sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc`
- Safe mode: on
- Excluded domains: payments.example.test
- Excluded paths: /admin

The digests above were pinned when the run started, so a later change to the authorization or the Rules of Engagement cannot alter what this report says was permitted.

## Risk summary

| Severity | Count |
|---|---|
| CRITICAL | 1 |
| HIGH | 1 |
| MEDIUM | 1 |
| LOW | 0 |
| INFORMATIONAL | 0 |

Scores come from the Aegis risk model (`impact × likelihood × confidence_weight × exposure_modifier`). Every finding carries the inputs that produced its score, and the severity follows a published banding — see the appendix. CVSS and AIVSS, where present, are separate figures and are never averaged into this score.

## Framework coverage

### Reported against

- **cwe**: CWE-78
- **mitre_atlas**: AML.T0051
- **owasp_asvs**: V5.3.8
- **owasp_llm**: LLM01, LLM06

### Not tested

- **dependency advisories** — Advisory lookup is disabled by default (no outbound disclosure).

A category listed as reported against means at least one finding cited it. It does not mean the category was exhaustively tested.

## Remediation plan

Ordered by risk score. Effort bands are not estimated by this tool.

1. **CRITICAL** (9.1/10) — Command built from unvalidated input, with a <script> in the snippet [app/handlers.py:42]
   Pass an argument list; never shell=True.
2. **HIGH** (7.4/10) — Direct prompt injection overrides the system instruction [POST /api/chat]
   Separate instructions from data; re-assert the system policy per turn.
3. **MEDIUM** (5.0/10) — Tool invocation is not scoped to the requesting user [declared tool: create_ticket]
   Bind tool calls to the authenticated principal.
