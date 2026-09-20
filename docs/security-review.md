# Security review

A self-review of Aegis AI Security, written for someone deciding whether to
run it. It states what the controls are, how each one was verified, and what is
deliberately not covered. Where a control is weaker than it might appear, that
is said here rather than left to be discovered.

Reviewed on branch `claude/ai-risk-security-platform-vc1nch`, through Phase 15.
The test count moves with every phase; `docs/roadmap.md` records what each one
added and what it deliberately left out.

## What this thing is, and why that matters

Aegis launches network requests on behalf of its caller and runs third-party
scanners against source it was pointed at. **It is SSRF-shaped by design.** The
scope engine is the only thing between it and abuse, so most of this document
is about that engine and the ways it could be circumvented.

Deploy it on a restricted network segment. `docs/threat-model.md` says the same
thing at more length.

## The controls, and how each was verified

### The scope engine is the single outbound control point

Every outbound request — API, worker, CLI, plugin, AI provider — goes through
`GatedTransport`. Verified three ways:

- a static test greps `app/` for `httpx.Client(`/`httpx.AsyncClient(` and fails
  on any construction outside `app/core/scope/transport.py`;
- the platform's own Semgrep rule (`aegis.ungated-http-client`) runs against
  this repository in `security.yml`, with exactly two annotated suppressions —
  the transport itself and the CLI's client, which talks to the Aegis API
  rather than to a target;
- the plugin tests assert that nothing reachable from the plugin contract is an
  HTTP client, that a plugin pointed at an out-of-scope host gets nothing, and
  that a plugin's requests count against the run's budget.

**Order matters and is tested:** exclusions are evaluated before allowlists,
DNS is re-resolved per request (so a name that resolved in-scope once cannot be
re-pointed), and redirects are never followed automatically.

### Private ranges are blocked; metadata endpoints cannot be unblocked

RFC1918, loopback, link-local and `0.0.0.0/8` are refused unless an operator
lists the range in `allowed_ip_ranges`. That override exists because scanning an
internal staging host is a real engagement, and so is scanning the demo lab on
its internal Docker network.

`169.254.169.254` and `fd00:ec2::254` are **not overridable**. They are not
targets; they are what hands out the credentials of the machine this platform
runs on, and leaving that behind a configuration flag would make one mistyped
allowlist the difference between a scanner and a credential thief. Tested with
allowlists as broad as `0.0.0.0/0`.

This was found during this review. Until then a wide `allowed_ip_ranges` would
have permitted the metadata endpoint.

### Authorization is a hard gate, checked per request

A run cannot start without an `Authorization` record naming a person, a role
and a validity window, and the window is checked on every request rather than
once at run start. Only Admin and Owner may grant one — asserted against the
route table, not by inspection.

### Tenant isolation and RBAC

`tests/security/test_authorization_matrix.py` walks the real route table and,
for every organization-scoped route:

- asserts it declares a minimum role (a new endpoint cannot join the API
  without one, because the test enumerates rather than reading a list);
- calls it unauthenticated and expects 401;
- calls it as a member of a different organization and expects **404, not 403**
  — 403 would confirm the organization exists;
- calls it as a role below its declared minimum and expects 403.

114 assertions, 2 skipped (the SSE stream, covered separately).

It also pins the route→role table. That was added after breaking the test on
purpose: downgrading a route from analyst to viewer passed every other
assertion, because a weakened route enforces its weaker declaration perfectly
well. A privilege change now has to be made deliberately, where a reviewer sees
it.

### Secrets are redacted before anything is written

`build_bundle` is the only sanctioned way to make an evidence bundle, and it
redacts headers by name, bodies, judge transcripts and the detector's own
verdict. `EvidenceStore.write` re-scans the serialized bytes and refuses,
naming what tripped it. A Hypothesis property test plants each of nine
credential shapes in arbitrary surrounding text and asserts the serialized
bundle discloses none of them.

Two real defects came out of that test:

- the patterns anchored on `\b`, so `AKIAIOSFODNN7EXAMPLE0` — a complete AWS key
  id plus one character — passed through unredacted. Adjacency is no longer a
  way past the detector;
- a run's canary is random, so whether it happened to clear the entropy
  threshold decided whether the run could store evidence at all. Markers are
  now exempt, which also means marker-based findings keep the evidence that
  makes them checkable.

### Evidence is content-addressed and hash-chained

Each bundle is named by its digest; each manifest entry carries the previous
entry's chain value. `verify` re-walks the chain *and* re-hashes every file, so
a bundle edited in place fails as loudly as one removed. Both failure modes are
tested by performing the tampering.

**Not encrypted at rest.** Filesystem permissions and pre-write redaction are
what protect a bundle. `.env.example` and the compose volume say so where an
operator will read them.

### API keys cannot escalate

A key's scopes are its authority and the role is derived from them, capped at
security engineer. A key therefore cannot create a target, amend an
authorization, add a member, or mint another key — tested by minting an owner's
key and attempting all four. Without that cap every CI key an owner created
would have been an owner key.

### The AI layer cannot act

`AIService` has no `execute`. It drafts; a human accepts. Capabilities are a
closed set, target-touching actions are refused at the type level, and evidence
is fenced as data before it reaches a model — the material this layer
summarises is harvested from injection probes, so passing it unfenced would
repeat the mistake the platform tests its clients for. A boundary test asserts
nothing in `core/` outside `core/assistant` imports the assistant, so the
platform works with the whole layer absent.

### Plugins are not sandboxed, and this is said everywhere

A plugin is Python in the worker process. Discovery is off until an operator
names a package; an optional hash pins the installed build. What is guaranteed
is that the contract offers no ungated route to a target, that metadata is
validated at load, that a plugin's attribution is overwritten so it cannot file
findings under a native probe's name, and that a plugin-supplied evidence
bundle is discarded.

### The demo lab cannot reach anything

Behind `--profile demo`, on a network declared `internal: true` (no gateway),
no published ports, `read_only`, `cap_drop: ALL`, no `env_file`. It refuses to
start if any of thirteen provider credential variables is set, binds loopback
unless told otherwise, uses a stub with no HTTP library, and prints a banner.
Each of those is a test, plus all ten seeded flaws, plus the compose
declarations.

## What is not covered

Stated plainly, because a review that lists only strengths is marketing.

| Gap | Consequence |
|---|---|
| No rate limiting on authentication endpoints | Online password guessing is bounded only by Argon2's cost |
| No server-side JWT revocation | A stolen session token is valid until it expires |
| No encryption at rest for evidence | A host compromise yields redacted evidence bundles |
| No CSRF token on cookie-authenticated routes | `SameSite=Lax` is the only protection |
| No signature verification for plugins | The allowlist and an optional hash are the controls |
| Container, license, EOL and malware scanning absent | The dependency picture is advisory-only |
| DAST absent | Nothing crawls; only declared surfaces are tested |
| `mapping_versions` empty | Framework mappings are unpinned, and say so |
| Advisory lookup off by default | SCA reports what is installed, not what is vulnerable, unless enabled |
| Four §23 workflows absent | `release.yml`, `framework-drift.yml` and two others are not written |
| No Sigstore signing | Releases are unsigned |

`docs/roadmap.md` carries the reasoning for each.

## Things that would worry me most

1. **An operator who allowlists a broad private range.** It is a legitimate
   feature and it is the widest door in the product. The metadata carve-out
   closes the worst case; nothing closes "I allowlisted 10.0.0.0/8 and scanned
   my own database".
2. **A plugin.** No sandbox, by design and by admission. The allowlist is only
   as good as the review of what goes on it.
3. **Authentication endpoints without rate limiting.** The oldest open item
   here, and the one most likely to matter first in a real deployment.

## How to re-run this review

```bash
cd backend
pytest -q                                    # everything
pytest tests/security -q                     # scope, authz, tenant isolation
pytest -m lab_e2e -q                         # a real assessment against the lab
semgrep --config app/core/appsec/sast/rules --error app aegis_cli
bandit -r app aegis_cli -ll
detect-secrets-hook --baseline .secrets.baseline $(git ls-files)
```

## Phase 15 additions: DAST

Two new controls, and one new gap stated plainly.

**Pre-queue scope checking.** The crawler checks a discovered URL through the
scope engine before it enters the queue, not before it is fetched. This is
stronger than the phase required, and the reasoning is in `docs/dast.md`. The
test asserts on the queue rather than on requests made, and was verified by
replacing the check with "queue everything" and watching it fail.

**Template policy derived from the rules of engagement.** Destructive Nuclei
tags and ZAP's active scan are unreachable unless `allow_state_mutation` is set.
Out-of-band callback templates are excluded even then, with `-no-interactsh`
passed as well so the tag exclusion is not a single point of failure. Verified
by weakening the policy to include the mutating tags unconditionally.

**The gap: the scanner adapters are not scope-gated at the socket.** Nuclei and
ZAP open their own connections. This is the weakest point in the phase.

- *Nuclei* is handed explicit `-target` URLs, each of which passed the scope
  engine during the crawl, and is not asked to discover more. It runs offline
  (`-disable-update-check`) and at the RoE's rate limit.
- *ZAP* spiders on its own and cannot be bounded that way. It therefore runs
  only when the rules of engagement name exactly one concrete host, and emits a
  visible `not tested` marker otherwise. Its report is written to a temporary
  directory and removed, because it contains response excerpts from the target.

If this platform grows a requirement that *all* outbound traffic be observable,
these two adapters are what would have to change — most likely by running them
behind a local proxy this platform controls, which is not built.
