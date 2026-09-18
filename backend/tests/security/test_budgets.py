"""Direct unit tests for BudgetTracker — the atomic reservation/reconciliation
primitive the scope engine's budget checks are built on."""

from app.core.scope.budgets import BudgetExceeded, BudgetTracker
from tests.security.conftest import make_budgets


async def test_peek_reports_tokens_received_exceeded_without_mutating() -> None:
    tracker = BudgetTracker(make_budgets(max_tokens_received=100))

    problem = tracker.peek(estimated_tokens_received=1000)

    assert isinstance(problem, BudgetExceeded)
    assert problem.dimension == "tokens_received"
    # peek() must not have reserved anything — a real reserve() for a small,
    # in-budget amount should still succeed afterwards.
    await tracker.reserve(estimated_tokens_received=10)


async def test_peek_returns_none_when_nothing_would_be_exceeded() -> None:
    tracker = BudgetTracker(make_budgets())

    assert tracker.peek() is None


async def test_reconcile_adjusts_running_totals_by_the_delta() -> None:
    tracker = BudgetTracker(make_budgets(max_tokens_sent=1000, max_tokens_received=1000))

    await tracker.reserve(estimated_tokens_sent=100, estimated_tokens_received=50)
    # Actual usage came in higher than estimated.
    await tracker.reconcile(
        estimated_tokens_sent=100,
        actual_tokens_sent=150,
        estimated_tokens_received=50,
        actual_tokens_received=80,
    )

    # tokens_sent is now 150 (the actual, not the 100 originally reserved),
    # leaving 850 of the 1000 budget — a further 900 should not fit.
    problem = tracker.peek(estimated_tokens_sent=900)
    assert isinstance(problem, BudgetExceeded)
    assert problem.dimension == "tokens_sent"

    # But a further 800 still fits against the true remaining 850.
    assert tracker.peek(estimated_tokens_sent=800) is None


async def test_reconcile_adjusts_cost_by_the_delta() -> None:
    tracker = BudgetTracker(make_budgets(max_estimated_cost_usd=10.0))

    await tracker.reserve(estimated_cost_usd=1.0)
    await tracker.reconcile(estimated_cost_usd=1.0, actual_cost_usd=0.5)  # came in cheaper

    # 10.0 budget, 0.5 actually used so far -> 9.4 more should still fit.
    assert tracker.peek(estimated_cost_usd=9.4) is None
