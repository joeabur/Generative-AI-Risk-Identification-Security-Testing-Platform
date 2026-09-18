# ADR 0004: Licence is Apache-2.0

## Status

Accepted

## Context

`docs/BUILD_SPEC.md` §25 specifies Apache-2.0 for this project, noting that
the patent grant matters for security tooling: Apache-2.0 §3 grants an
express, irrevocable patent license from every contributor for their
contributions, and terminates that grant for anyone who initiates patent
litigation over the project. For a dual-use security-testing tool — one
whose probes and techniques are exactly the kind of thing patent disputes
tend to target — that explicit grant is worth more than the marginal
permissiveness MIT would add.

## Decision

Licence the project under Apache-2.0. The `LICENSE` file at the repository
root carries the standard Apache-2.0 text unmodified.

## Consequences

- Every source file may carry a short SPDX header (`SPDX-License-Identifier:
  Apache-2.0`) as the project grows; not retrofitted onto Phase 1 files
  individually, to avoid churn — apply it going forward from Phase 2.
- Third-party dependencies and integrated tools (`docs/third-party.md`, not
  yet written) must each be checked for licence compatibility with
  Apache-2.0 before integration, per `docs/BUILD_SPEC.md` §15.
