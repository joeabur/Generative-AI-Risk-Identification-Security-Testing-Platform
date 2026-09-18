"""Pure, DB-independent domain types for the scope engine.

These are deliberately plain frozen dataclasses, not SQLAlchemy models: the
engine that reads them must be usable from the API, a Celery worker, and the
CLI alike, and must be testable without a database. `app/models/target.py`
(the persisted form) is resolved into these via `app/core/scope/resolve.py`.
"""

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class Budgets:
    max_requests: int
    max_concurrency: int
    requests_per_second: float
    max_tokens_sent: int
    max_tokens_received: int
    max_estimated_cost_usd: float
    max_wall_clock_minutes: int


@dataclass(frozen=True)
class BlackoutWindow:
    starts_at: datetime
    ends_at: datetime

    def contains(self, moment: datetime) -> bool:
        return self.starts_at <= moment <= self.ends_at


@dataclass(frozen=True)
class RulesOfEngagement:
    allowed_domains: tuple[str, ...]
    excluded_domains: tuple[str, ...]
    allowed_ip_ranges: tuple[str, ...]
    allowed_paths: tuple[str, ...]
    excluded_paths: tuple[str, ...]
    allowed_methods: tuple[str, ...]
    forbidden_headers: tuple[str, ...]
    budgets: Budgets
    safe_mode: bool = True
    blackout_windows: tuple[BlackoutWindow, ...] = ()


@dataclass(frozen=True)
class ResolvedAuthorization:
    valid_from: datetime
    valid_until: datetime


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    rule: str
    reason: str
    halted: bool = False
