"""Run-lifecycle tests for the DB-free orchestrator (docs/BUILD_SPEC.md §15).

These exercise the engine with a real `GatedTransport` and a real
`ScopeEngine` — only DNS and the network itself are faked — so the halt
paths under test are the ones production takes, not a mock of them.
"""

from datetime import timedelta

import pytest
import respx
from httpx import Response

from app.core.orchestrator.checks import CheckResult, Endpoint, ReachabilityCheck
from app.core.orchestrator.runner import (
    EventKind,
    RunEventPayload,
    RunOutcomeStatus,
    execute_run,
)
from app.core.scope.context import RunContext
from app.core.scope.engine import ScopeEngine
from app.core.scope.transport import GatedTransport
from tests.security.conftest import (
    FakeClock,
    FakeDnsResolver,
    make_authorization,
    make_budgets,
    make_context,
    make_roe,
)

BASE_URL = "https://ai.example.test"


@pytest.fixture
def fake_dns() -> FakeDnsResolver:
    return FakeDnsResolver({"ai.example.test": ["203.0.113.5"]})


class _Recorder:
    def __init__(self) -> None:
        self.events: list[RunEventPayload] = []

    async def __call__(self, event: RunEventPayload) -> None:
        self.events.append(event)

    def kinds(self) -> list[EventKind]:
        return [event.kind for event in self.events]


def _transport(fake_dns: FakeDnsResolver) -> GatedTransport:
    return GatedTransport(engine=ScopeEngine(), dns_resolver=fake_dns)


def _check(*paths: str) -> ReachabilityCheck:
    return ReachabilityCheck(BASE_URL, [Endpoint(method="GET", path=path) for path in paths])


async def test_run_completes_and_emits_real_progress(fake_dns: FakeDnsResolver) -> None:
    ctx = make_context()
    emit = _Recorder()

    with respx.mock() as router:
        router.get(f"{BASE_URL}/a").mock(return_value=Response(200))
        router.get(f"{BASE_URL}/b").mock(return_value=Response(404))
        outcome = await execute_run(ctx, [_check("/a", "/b")], _transport(fake_dns), emit)

    assert outcome.status is RunOutcomeStatus.COMPLETED
    assert outcome.checks_completed == outcome.checks_total == 1
    assert [result.status_code for result in outcome.results] == [200, 404]
    assert outcome.halted_reason is None
    # Progress is emitted from work that actually happened, in order.
    assert emit.kinds() == [
        EventKind.STARTED,
        EventKind.CHECK_STARTED,
        EventKind.CHECK_COMPLETED,
        EventKind.COMPLETED,
    ]


async def test_blocked_endpoint_is_recorded_not_raised(fake_dns: FakeDnsResolver) -> None:
    """A path the RoE excludes is a normal recorded outcome with its rule."""
    ctx = make_context(roe=make_roe(excluded_paths=("/admin",)))
    emit = _Recorder()

    with respx.mock(assert_all_called=False) as router:
        allowed = router.get(f"{BASE_URL}/a").mock(return_value=Response(200))
        forbidden = router.get(f"{BASE_URL}/admin").mock(return_value=Response(200))
        outcome = await execute_run(ctx, [_check("/a", "/admin")], _transport(fake_dns), emit)

        assert allowed.call_count == 1
        assert forbidden.call_count == 0

    assert outcome.status is RunOutcomeStatus.COMPLETED
    assert outcome.requests_blocked == 1
    blocked = [result for result in outcome.results if result.blocked_rule is not None]
    assert blocked[0].blocked_rule == "excluded_path"
    assert EventKind.REQUEST_BLOCKED in emit.kinds()


async def test_tripped_kill_switch_ends_the_run_as_cancelled(fake_dns: FakeDnsResolver) -> None:
    ctx = make_context()
    ctx.kill_switch.trip()
    emit = _Recorder()

    with respx.mock(assert_all_called=False) as router:
        route = router.get(f"{BASE_URL}/a").mock(return_value=Response(200))
        outcome = await execute_run(ctx, [_check("/a")], _transport(fake_dns), emit)
        assert route.call_count == 0

    assert outcome.status is RunOutcomeStatus.CANCELLED
    assert outcome.checks_completed == 0
    assert EventKind.CANCELLED in emit.kinds()


async def test_cancellation_mid_run_stops_within_one_request(fake_dns: FakeDnsResolver) -> None:
    """A probe that flips the external cancellation flag must stop the run at
    the next scope check, not at the next check boundary."""
    cancelled = False

    def probe() -> bool:
        return cancelled

    ctx = make_context()
    from app.core.scope.kill_switch import KillSwitch

    ctx.kill_switch = KillSwitch(probe=probe)
    emit = _Recorder()

    with respx.mock(assert_all_called=False) as router:

        def _first(request: object) -> Response:
            nonlocal cancelled
            cancelled = True
            return Response(200)

        router.get(f"{BASE_URL}/a").mock(side_effect=_first)
        second = router.get(f"{BASE_URL}/b").mock(return_value=Response(200))
        outcome = await execute_run(ctx, [_check("/a", "/b")], _transport(fake_dns), emit)

        assert second.call_count == 0

    assert outcome.status is RunOutcomeStatus.CANCELLED
    assert outcome.halted_reason == "kill switch tripped"


async def test_budget_exhaustion_is_a_partial_but_valid_completed_run(
    fake_dns: FakeDnsResolver,
) -> None:
    """Running out of budget is not a failure — the run completed as far as
    its budget allowed, and the halt reason says so (§14 coverage honesty)."""
    ctx = make_context(roe=make_roe(budgets=make_budgets(max_requests=1)))
    emit = _Recorder()

    with respx.mock(assert_all_called=False) as router:
        route = router.get(f"{BASE_URL}/a").mock(return_value=Response(200))
        router.get(f"{BASE_URL}/b").mock(return_value=Response(200))
        outcome = await execute_run(ctx, [_check("/a", "/b")], _transport(fake_dns), emit)
        assert route.call_count == 1

    assert outcome.status is RunOutcomeStatus.COMPLETED
    assert outcome.halted_reason == "requests budget exceeded"
    assert outcome.requests_blocked == 1


async def test_authorization_expiring_mid_run_ends_the_run_as_expired(
    fake_dns: FakeDnsResolver,
) -> None:
    clock = FakeClock()
    roe = make_roe()
    ctx = RunContext(
        roe=roe,
        authorization=make_authorization(
            clock=clock, valid_until=clock.now() + timedelta(minutes=5)
        ),
        budgets=make_context(roe=roe, clock=clock).budgets,
        kill_switch=make_context().kill_switch,
        clock=clock.now,
    )
    emit = _Recorder()

    with respx.mock(assert_all_called=False) as router:

        def _expire(request: object) -> Response:
            clock.advance(minutes=10)
            return Response(200)

        router.get(f"{BASE_URL}/a").mock(side_effect=_expire)
        second = router.get(f"{BASE_URL}/b").mock(return_value=Response(200))
        outcome = await execute_run(ctx, [_check("/a", "/b")], _transport(fake_dns), emit)
        assert second.call_count == 0

    assert outcome.status is RunOutcomeStatus.EXPIRED
    assert outcome.halted_reason == "authorization is not currently valid"


async def test_a_check_that_raises_fails_the_run_with_its_identity() -> None:
    class ExplodingCheck:
        id = "test.explode"
        name = "Exploding check"

        async def run(self, ctx: RunContext, transport: GatedTransport) -> list[CheckResult]:
            raise RuntimeError("boom")

    ctx = make_context()
    emit = _Recorder()
    outcome = await execute_run(ctx, [ExplodingCheck()], GatedTransport(), emit)

    assert outcome.status is RunOutcomeStatus.FAILED
    assert outcome.error_message is not None
    assert "test.explode" in outcome.error_message
    assert emit.kinds()[-1] is EventKind.FAILED


async def test_unreachable_target_is_a_result_not_a_crash(fake_dns: FakeDnsResolver) -> None:
    import httpx

    ctx = make_context()
    emit = _Recorder()

    with respx.mock() as router:
        router.get(f"{BASE_URL}/a").mock(side_effect=httpx.ConnectError("refused"))
        outcome = await execute_run(ctx, [_check("/a")], _transport(fake_dns), emit)

    assert outcome.status is RunOutcomeStatus.COMPLETED
    assert outcome.results[0].ok is False
    assert "request failed" in outcome.results[0].detail
