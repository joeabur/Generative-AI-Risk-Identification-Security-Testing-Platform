import asyncio
import time
from collections.abc import Callable

from app.core.scope.models import Budgets


class BudgetExceeded(Exception):
    def __init__(self, dimension: str, message: str) -> None:
        super().__init__(message)
        self.dimension = dimension


class BudgetTracker:
    """Atomic, in-memory tracking of a single run's resource consumption.

    `reserve()` is the single choke point: it checks every dimension
    (requests, tokens, cost, wall-clock) and only commits the reservation if
    none would be exceeded — under one lock, so concurrent callers can never
    both squeeze through on the same last unit of budget. Concurrency itself
    is capped separately via `acquire_concurrency()`, an `asyncio.Semaphore`.
    """

    def __init__(self, budgets: Budgets, *, clock: Callable[[], float] | None = None) -> None:
        self._budgets = budgets
        self._clock = clock or time.monotonic
        self._start = self._clock()
        self._lock = asyncio.Lock()
        self._requests_used = 0
        self._tokens_sent = 0
        self._tokens_received = 0
        self._cost_used_usd = 0.0
        self._semaphore = asyncio.Semaphore(budgets.max_concurrency)

    @property
    def elapsed_minutes(self) -> float:
        return (self._clock() - self._start) / 60

    def acquire_concurrency(self) -> asyncio.Semaphore:
        return self._semaphore

    def peek(
        self,
        *,
        estimated_tokens_sent: int = 0,
        estimated_tokens_received: int = 0,
        estimated_cost_usd: float = 0.0,
    ) -> BudgetExceeded | None:
        """Non-mutating version of `reserve()` for dry-run previews: reports
        what *would* happen without committing a reservation."""
        if self.elapsed_minutes > self._budgets.max_wall_clock_minutes:
            return BudgetExceeded("wall_clock", "wall-clock budget exceeded")
        if self._requests_used + 1 > self._budgets.max_requests:
            return BudgetExceeded("requests", "request budget exceeded")
        if self._tokens_sent + estimated_tokens_sent > self._budgets.max_tokens_sent:
            return BudgetExceeded("tokens_sent", "sent-token budget exceeded")
        if self._tokens_received + estimated_tokens_received > self._budgets.max_tokens_received:
            return BudgetExceeded("tokens_received", "received-token budget exceeded")
        if self._cost_used_usd + estimated_cost_usd > self._budgets.max_estimated_cost_usd:
            return BudgetExceeded("cost", "cost budget exceeded")
        return None

    async def reserve(
        self,
        *,
        estimated_tokens_sent: int = 0,
        estimated_tokens_received: int = 0,
        estimated_cost_usd: float = 0.0,
    ) -> None:
        async with self._lock:
            if self.elapsed_minutes > self._budgets.max_wall_clock_minutes:
                raise BudgetExceeded("wall_clock", "wall-clock budget exceeded")
            if self._requests_used + 1 > self._budgets.max_requests:
                raise BudgetExceeded("requests", "request budget exceeded")
            if self._tokens_sent + estimated_tokens_sent > self._budgets.max_tokens_sent:
                raise BudgetExceeded("tokens_sent", "sent-token budget exceeded")
            if (
                self._tokens_received + estimated_tokens_received
                > self._budgets.max_tokens_received
            ):
                raise BudgetExceeded("tokens_received", "received-token budget exceeded")
            if self._cost_used_usd + estimated_cost_usd > self._budgets.max_estimated_cost_usd:
                raise BudgetExceeded("cost", "cost budget exceeded")

            self._requests_used += 1
            self._tokens_sent += estimated_tokens_sent
            self._tokens_received += estimated_tokens_received
            self._cost_used_usd += estimated_cost_usd

    async def reconcile(
        self,
        *,
        estimated_tokens_sent: int = 0,
        actual_tokens_sent: int = 0,
        estimated_tokens_received: int = 0,
        actual_tokens_received: int = 0,
        estimated_cost_usd: float = 0.0,
        actual_cost_usd: float = 0.0,
    ) -> None:
        """Post-flight adjustment once real usage is known (§7.2/§13).

        The pre-flight `reserve()` call already added the *estimate* to the
        running totals; this replaces that estimate with the real number
        (by adjusting for the delta) so the next `reserve()` call checks
        against accurate consumption, without re-validating the budget for
        the request that already happened.
        """
        async with self._lock:
            self._tokens_sent += actual_tokens_sent - estimated_tokens_sent
            self._tokens_received += actual_tokens_received - estimated_tokens_received
            self._cost_used_usd += actual_cost_usd - estimated_cost_usd
