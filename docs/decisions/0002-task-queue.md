# ADR 0002: Task queue is Celery, with `arq` as a documented fallback

## Status

Accepted (default); open to revision during Phase 1 implementation

## Context

The scan orchestrator needs a background-job system: assessments run for minutes, must report real-time
progress to a browser, must be cancellable, and must survive a worker restart without losing budget/audit
state. The Master Build Prompt specifies Celery explicitly. Celery is heavier operationally (typically needs
a result backend, careful task idempotency handling, and more configuration) than lighter alternatives such
as `arq`, which is asyncio-native and pairs more naturally with the rest of the backend's `async`/`httpx`
stack.

## Decision

Default to Celery, per the explicit product specification. If Phase 1 implementation shows Celery's
synchronous-worker model fighting the scope engine's async transport (e.g. requiring a sync-to-async bridge
for every scoped request), switch to `arq` instead — but only as an explicit decision recorded here, not a
silent substitution.

## Consequences

- Worker code in `backend/app/workers/` is written as a thin adapter over `core/orchestrator/`, so the
  choice of queue library stays swappable without touching business logic.
- Redis is required regardless of which queue library is used (Celery broker, or `arq`'s native Redis use).
