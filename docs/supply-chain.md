# Supply-chain scanning

Aegis ships four engines that answer questions an advisory database cannot.
That framing is the point of this document: each of these exists precisely
because there is **no CVE** behind the risk, which is why an advisory-only
scanner reports the affected repository as clean.

| Engine | Rule IDs | Question |
|---|---|---|
| End-of-life runtime | `AEGIS-SUPPLY-010/011/019` | Is this runtime still getting security patches? |
| Dependency licence risk | `AEGIS-SUPPLY-020…023` | What obligations do these dependencies carry? |
| Name confusion | `AEGIS-SUPPLY-030/031/032` | Is this package the one you meant? |
| Container dependency scan | `AEGIS-CONTAINER-001/009` | What vulnerable packages ship in the image? |

None of the first three reach the network. The fourth runs Trivy offline.

## End-of-life runtimes

An end-of-life runtime has no CVE, and that *is* the problem: nothing will be
assigned, nothing will be backported, and the next vulnerability found in it
simply stays open.

The EOL data is **vendored with a snapshot date** rather than fetched, for the
same reason `pip-audit`'s advisory lookup is opt-in — sending a client's runtime
inventory to a third party is a disclosure decision an operator makes, not one a
scanner makes quietly. The cost is staleness, handled explicitly:

* `AS_OF` (the compile date) appears in **every** finding, so a reader can tell
  "supported as of six months ago" from "supported today".
* A runtime or series **not in the table is reported as not assessed**
  (`AEGIS-SUPPLY-019`), never as supported. Absence of data is not evidence of
  support, and this is the one mistake that would make the engine misleading.
* Severity grows with age (LOW → MEDIUM at 180 days → HIGH at 730) and is
  **capped below CRITICAL**. A standing exposure is not a demonstrated exploit;
  §11 reserves the top band for what was shown to work, and calling every old
  base image critical devalues the findings that are.

Sources read: `Dockerfile*` `FROM` lines (every stage, including build stages —
a stage with an ancient base still executes), `.python-version`, `.nvmrc`,
`go.mod`, and `package.json` `engines`.

## Licence risk

This engine reports **obligations, not violations**. Whether AGPL-3.0 is a
problem depends on whether the product is distributed, hosted, or itself open
source — facts the scanner does not have. Emitting "licence violation" without
them is the confident-and-wrong finding that teaches a team to ignore a tool.

Bands, and what each triggers on:

| Band | Trigger |
|---|---|
| `network_copyleft` | AGPL, SSPL, OSL — **use over a network** counts as distribution |
| `strong_copyleft` | GPL — distributing a derivative work |
| `weak_copyleft` | LGPL, MPL, EPL, CDDL — file- or library-level obligations |
| `permissive` | MIT, BSD, Apache, ISC — attribution (plus Apache's patent grant) |
| `public_domain` | CC0, Unlicense, 0BSD |
| `proprietary_or_unknown` | anything unrecognised, **including missing** |

A missing licence is never treated as permission: it is the absence of a grant.
Permissive and public-domain dependencies get **no finding** — one per MIT
dependency is noise that buries the two that matter.

A compound expression classifies at its **strictest** component: `MIT OR
GPL-3.0` reports at the GPL level, even though the `OR` means a permissive
choice is available, because taking the looser reading would make the finding
depend on a choice nobody recorded making.

Licence data comes from installed metadata by default (`License-Expression`,
then a short `License` field, then a Trove classifier mapped through
`CLASSIFIER_TO_SPDX`). The lookup is an **injectable seam**
(`LicenseRiskEngine(lookup=…)`) because which source is available differs per
deployment — installed metadata, a lock file that records licences, or an
existing SBOM.

## Name confusion

The obvious version of this check is worse than nothing, so the framing is
careful. A name-similarity score is **not** evidence of malice:
`python-dateutil` and `dateutil` differ by an edit distance that would flag
either as squatting the other, and both are real.

So these findings are **signals for a human**, at LOW or INFORMATIONAL severity
with `DESIGN_REVIEW` confidence, and none of them says "malicious" or "malware".
Detected shapes:

* homoglyph substitution (`1odash` for `lodash`, `rn`/`m`, `0`/`o`, `5`/`s`)
* **adjacent transposition** (`reqeusts` for `requests`) — checked separately
  because Levenshtein scores a swap as two edits, so catching it via a wider
  distance cap would also admit genuinely different names
* one-character difference, only for names of five characters or more
* a popular name with a prefix or suffix bolted on (`python-requests`)
* unpinned versions (`AEGIS-SUPPLY-031`) — a build takes whatever the registry
  serves, so a compromised release arrives with no change on this side
* npm install hooks (`AEGIS-SUPPLY-032`) — not a vulnerability, since plenty of
  legitimate packages build native code this way, but it is where an
  install-time supply-chain attack lands

**No registry is consulted.** Asking "does a package with this name exist
upstream?" would send the client's dependency list to a third party. Without
that, dependency confusion cannot be established, and the finding says so
rather than implying otherwise.

The popular-name list is short and hand-maintained. A long generated list would
produce many low-value near-matches, and the whole value of this check is its
precision.

## Container scanning

**Filesystem mode, not `docker pull`.** Pulling the base image a Dockerfile
names would mean reaching a registry the operator has not sanctioned, as an
outbound request this platform's transport would never see, and materialising an
untrusted image on the worker. So the engine scans the checkout that was already
cloned under the code scope — which covers the lock files and vendored
dependencies making up most of an image's content.

`AEGIS-CONTAINER-009` then states plainly that **base image layers were not
examined**. Without it, a clean result would read as "the image is clean" when
the layers underneath the application were never looked at.

Trivy runs with `--skip-db-update --offline-scan`, matching against whatever
database the worker already has. A worker with no database yields a "not tested"
result (`AEGIS-APPSEC-000`), never a clean one. Every vulnerability identifier
is verified to be a real CVE/GHSA/OSV shape before it reaches a finding.

## What is not built

Recorded rather than half-built:

* **No registry lookup**, so no true dependency-confusion detection (does this
  private name also exist publicly?) and no "package published yesterday by a
  brand-new maintainer" signal. Both need an authorized outbound path and an
  operator's disclosure decision.
* **No image-layer scan**, per above.
* **No malware analysis.** The engine reports *where* install-time code runs; it
  does not analyse what that code does. Claiming otherwise would be the
  fake-functionality this project refuses.
* **No reachability analysis.** A vulnerable package being present does not
  establish that the affected code path is used — every finding says so.
* **A floating base image tag is not reported.** `FROM python:latest` and a
  digest-only pin declare no version, so there is nothing to compare against a
  support schedule and the EOL engine skips them. An unpinned base image is a
  real finding of its own — it just is not this engine's.
* **No SBOM export from these engines** specifically; the dependency inventory
  that feeds an SBOM comes from `pip-audit`.
* **No license policy configuration.** There is no way yet to say "AGPL is
  forbidden here" and have the CI gate fail on it; the findings are reported and
  a human decides.
