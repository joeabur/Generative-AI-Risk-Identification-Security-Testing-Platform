"""Run execution (docs/BUILD_SPEC.md §15, §26 Phase 4).

Deliberately DB-free: the runner reports what happened through an `emit`
callback and returns an outcome, and the caller (the Celery task) decides
how to persist it. That keeps the lifecycle logic testable without a
database and keeps `core/` free of storage concerns.

The run's terminal status is derived from *why* it stopped, which matters
for honesty in reporting: a run halted because its authorization expired
mid-flight is `expired`, one an operator stopped is `cancelled`, and one
that ran out of budget is `completed` with a halt reason — partial, but not
a failure, and the report must say which (§14 coverage honesty).
"""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import StrEnum

from app.core.orchestrator.checks import Check, CheckResult, requires_network
from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport


class RunOutcomeStatus(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class EventKind(StrEnum):
    STARTED = "started"
    CHECK_STARTED = "check_started"
    CHECK_COMPLETED = "check_completed"
    REQUEST_BLOCKED = "request_blocked"
    HALTED = "halted"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class RunEventPayload:
    kind: EventKind
    message: str
    data: dict[str, object] = field(default_factory=dict)


Emit = Callable[[RunEventPayload], Awaitable[None]]


@dataclass
class RunOutcome:
    status: RunOutcomeStatus
    checks_total: int
    checks_completed: int = 0
    requests_blocked: int = 0
    results: list[CheckResult] = field(default_factory=list)
    halted_reason: str | None = None
    error_message: str | None = None


async def execute_run(
    ctx: RunContext, checks: list[Check], transport: GatedTransport, emit: Emit
) -> RunOutcome:
    outcome = RunOutcome(status=RunOutcomeStatus.COMPLETED, checks_total=len(checks))
    await emit(RunEventPayload(EventKind.STARTED, f"Run started with {len(checks)} check(s)"))

    for check in checks:
        if ctx.kill_switch.tripped:
            # A run cancelled before its first check never reaches the scope
            # engine, so nothing else would set a halt reason here.
            ctx.halt("kill switch tripped")
            break
        if ctx.halted and requires_network(check):
            # Halted means no more requests may be sent. It does not mean a
            # check that reads files has nothing left to contribute, so those
            # still run; an operator cancellation is handled above and stops
            # everything.
            continue
        await emit(
            RunEventPayload(EventKind.CHECK_STARTED, f"{check.name} started", {"check": check.id})
        )
        try:
            results = await check.run(ctx, transport)
        except Exception as exc:  # noqa: BLE001 - one bad check must not lose the whole run
            outcome.status = RunOutcomeStatus.FAILED
            outcome.error_message = f"{check.id} raised: {exc}"
            await emit(
                RunEventPayload(EventKind.FAILED, outcome.error_message, {"check": check.id})
            )
            return outcome

        outcome.results.extend(results)
        for result in results:
            if result.blocked_rule is not None:
                outcome.requests_blocked += 1
                await emit(
                    RunEventPayload(
                        EventKind.REQUEST_BLOCKED,
                        f"{result.surface} blocked: {result.blocked_rule}",
                        {"surface": result.surface, "rule": result.blocked_rule},
                    )
                )

        outcome.checks_completed += 1
        await emit(
            RunEventPayload(
                EventKind.CHECK_COMPLETED,
                f"{check.name} completed ({len(results)} result(s))",
                {"check": check.id, "results": len(results)},
            )
        )

    if ctx.halted or ctx.kill_switch.tripped:
        outcome.halted_reason = ctx.halted_reason or "stopped before completion"
        outcome.status = _status_for_halt(outcome.halted_reason)
        await emit(
            RunEventPayload(
                EventKind.HALTED,
                f"Run halted: {outcome.halted_reason}",
                {"status": outcome.status.value},
            )
        )

    terminal = EventKind.COMPLETED
    if outcome.status is RunOutcomeStatus.CANCELLED:
        terminal = EventKind.CANCELLED
    elif outcome.status is RunOutcomeStatus.FAILED:
        terminal = EventKind.FAILED
    await emit(
        RunEventPayload(
            terminal,
            f"Run finished as {outcome.status.value} "
            f"({outcome.checks_completed}/{outcome.checks_total} checks)",
            {"status": outcome.status.value},
        )
    )
    return outcome


def _status_for_halt(reason: str) -> RunOutcomeStatus:
    """A halt is not automatically a failure. Budget exhaustion produces a
    partial but valid run; only an expired authorization or an operator
    cancellation get their own terminal status."""
    lowered = reason.lower()
    if "kill switch" in lowered:
        return RunOutcomeStatus.CANCELLED
    if "authorization" in lowered:
        return RunOutcomeStatus.EXPIRED
    return RunOutcomeStatus.COMPLETED
