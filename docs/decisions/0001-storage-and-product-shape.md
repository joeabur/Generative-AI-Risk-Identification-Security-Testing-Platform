# ADR 0001: Product shape is a multi-tenant web app; storage is PostgreSQL + Redis + Celery from Phase 1

## Status

Accepted

## Context

Two source specifications were merged into `docs/BUILD_SPEC.md`. One (the "v2.0" spec) treated this as a
single-operator CLI tool, defaulting to SQLite and in-process asyncio, with FastAPI and a minimal dashboard
added only in later phases as optional surfaces. The other (the "Master Build Prompt") specified a full
multi-tenant web application with organizations, RBAC, a Next.js frontend, and PostgreSQL/Redis/Celery from
the start.

These are incompatible defaults for Phase 1.

## Decision

The product is a multi-tenant web application first. PostgreSQL, Redis, and Celery are used from Phase 1,
not offered as an optional "scale profile." The CLI is a first-class client of the same REST API used by the
browser, not a separate, lighter-weight code path.

## Rationale

The single-operator/SQLite rationale ("an assessment tool is operated by one engineer against one target far
more often than it runs as a shared service") does not hold once the product requirement includes
organizations, concurrent users, role-based access control, and real-time scan progress rendered in a
browser for a team. Those requirements need a real multi-writer database and a background-job broker
regardless of scale — there is no meaningful "small" deployment of this product that avoids them. Offering
SQLite as a parallel profile would only fragment testing and scope-enforcement verification effort across
two storage backends for no correctness benefit, which is exactly the failure mode the original SQLite
rationale was trying to avoid.

## Consequences

- `docker compose up --build` starts five services (frontend, backend, worker, postgres, redis) from Phase 1,
  not one.
- All scope-engine and tenant-isolation tests must pass against Postgres, not SQLite, from the first release.
- Celery is the default task queue; if its operational overhead proves disproportionate during Phase 1
  implementation, revisit in favor of `arq` per `docs/decisions/0002-task-queue.md`, but do not silently
  drift between the two — the switch must be an explicit, documented decision.
