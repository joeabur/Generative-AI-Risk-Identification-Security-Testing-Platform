"""Celery tasks. Thin wrappers over `core/` — the lifecycle logic lives in
`app/core/orchestrator/runner.py` and is unit-tested without Celery or a
broker; `execute_assessment_run` below is the async implementation the task
delegates to, and tests call it directly.
"""

import asyncio
import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.orchestrator.checks import Check, Endpoint, ReachabilityCheck
from app.core.orchestrator.context_builder import build_run_context
from app.core.orchestrator.runner import RunEventPayload, execute_run
from app.core.scope.errors import AuthorizationRequiredError, RoEValidationError
from app.core.scope.kill_switch import KillSwitch
from app.core.scope.transport import GatedTransport
from app.db.session import dispose_engine, get_session_factory
from app.models.assessment_run import AssessmentRun, RunEvent, RunEventKind, RunStatus
from app.models.surface_endpoint import SurfaceEndpoint
from app.models.target import Target
from app.workers.cancellation import is_cancellation_requested
from app.workers.celery_app import celery_app

logger = structlog.get_logger()


def _digest(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def _record_event(
    db: AsyncSession, run_id: uuid.UUID, kind: RunEventKind, message: str, payload: dict[str, Any]
) -> None:
    db.add(RunEvent(run_id=run_id, kind=kind, message=message[:1000], payload=payload or None))
    await db.commit()


async def _load_run(db: AsyncSession, run_id: uuid.UUID) -> AssessmentRun | None:
    result = await db.execute(
        select(AssessmentRun)
        .where(AssessmentRun.id == run_id)
        .options(
            selectinload(AssessmentRun.target).selectinload(Target.authorization),
            selectinload(AssessmentRun.target).selectinload(Target.rules_of_engagement),
        )
    )
    return result.scalar_one_or_none()


async def _enabled_endpoints(db: AsyncSession, target_id: uuid.UUID) -> list[Endpoint]:
    result = await db.execute(
        select(SurfaceEndpoint)
        .where(SurfaceEndpoint.target_id == target_id, SurfaceEndpoint.enabled.is_(True))
        .order_by(SurfaceEndpoint.path, SurfaceEndpoint.method)
    )
    return [Endpoint(method=row.method, path=row.path) for row in result.scalars().all()]


async def execute_assessment_run(
    run_id: uuid.UUID, transport: GatedTransport | None = None
) -> RunStatus:
    """Run one assessment to a terminal state, persisting progress as it goes.

    `transport` exists so tests can inject a resolver-and-network double; in
    production it is always the default `GatedTransport`, which is still the
    only path to the network either way.
    """
    session_factory = get_session_factory()

    async with session_factory() as db:
        run = await _load_run(db, run_id)
        if run is None:
            logger.warning("run_not_found", run_id=str(run_id))
            return RunStatus.FAILED
        if run.status not in {RunStatus.QUEUED, RunStatus.DRAFT}:
            # Already started, finished, or cancelled before the worker picked
            # it up — never restart a run that has left the queue.
            return run.status

        target = run.target

        try:
            ctx = build_run_context(target)
        except (AuthorizationRequiredError, RoEValidationError) as exc:
            run.status = RunStatus.FAILED
            run.error_message = str(exc)
            run.finished_at = datetime.now(UTC)
            await db.commit()
            await _record_event(db, run.id, RunEventKind.FAILED, str(exc), {})
            return RunStatus.FAILED

        # The switch latches, so a cancellation requested at any point stops
        # the run at the next scope check rather than at the next check boundary.
        ctx.kill_switch = KillSwitch(probe=lambda: is_cancellation_requested(str(run_id)))

        endpoints = await _enabled_endpoints(db, target.id)
        checks: list[Check] = [ReachabilityCheck(target.base_url, endpoints)]

        run.status = RunStatus.RUNNING
        run.started_at = datetime.now(UTC)
        run.checks_total = len(checks)
        run.authorization_digest = _digest(
            {
                "valid_from": ctx.authorization.valid_from,
                "valid_until": ctx.authorization.valid_until,
            }
        )
        run.roe_digest = _digest(
            {
                "allowed_domains": list(ctx.roe.allowed_domains),
                "excluded_domains": list(ctx.roe.excluded_domains),
                "allowed_ip_ranges": list(ctx.roe.allowed_ip_ranges),
                "allowed_paths": list(ctx.roe.allowed_paths),
                "excluded_paths": list(ctx.roe.excluded_paths),
                "allowed_methods": list(ctx.roe.allowed_methods),
                "safe_mode": ctx.roe.safe_mode,
            }
        )
        await db.commit()

        async def emit(event: RunEventPayload) -> None:
            await _record_event(
                db, run.id, RunEventKind(event.kind.value), event.message, dict(event.data)
            )

        outcome = await execute_run(ctx, checks, transport or GatedTransport(), emit)

        run.status = RunStatus(outcome.status.value)
        run.checks_completed = outcome.checks_completed
        run.requests_blocked = outcome.requests_blocked
        run.requests_used = len(outcome.results)
        run.halted_reason = outcome.halted_reason
        run.error_message = outcome.error_message
        run.finished_at = datetime.now(UTC)
        await db.commit()

        logger.info(
            "run_finished",
            run_id=str(run_id),
            status=run.status.value,
            checks=f"{outcome.checks_completed}/{outcome.checks_total}",
        )
        return run.status


@celery_app.task(name="aegis.run_assessment")
def run_assessment(run_id: str) -> str:
    """Celery's synchronous entry point.

    Each task gets its own event loop, and asyncpg connections belong to the
    loop that opened them, so the engine is disposed before the loop closes
    rather than left holding connections the next task cannot use.
    """

    async def _run() -> RunStatus:
        try:
            return await execute_assessment_run(uuid.UUID(run_id))
        finally:
            await dispose_engine()

    return asyncio.run(_run()).value
