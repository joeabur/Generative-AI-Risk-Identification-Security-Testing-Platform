from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.core.scope.budgets import BudgetTracker
from app.core.scope.kill_switch import KillSwitch
from app.core.scope.models import ResolvedAuthorization, RulesOfEngagement


@dataclass
class RunContext:
    """The state threaded through every scope check for one assessment run.

    `halted` is sticky: once any check sets it, every subsequent check on
    this context is blocked immediately without re-evaluating the specific
    rule that tripped it, per docs/BUILD_SPEC.md §6.2 ("run halts").
    """

    roe: RulesOfEngagement
    authorization: ResolvedAuthorization
    budgets: BudgetTracker
    kill_switch: KillSwitch
    clock: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))
    halted: bool = False
    halted_reason: str | None = None

    def halt(self, reason: str) -> None:
        self.halted = True
        self.halted_reason = reason
