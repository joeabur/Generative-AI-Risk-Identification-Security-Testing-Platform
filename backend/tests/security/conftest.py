"""Shared fixtures for the release-blocking scope-engine test matrix.

Everything here is a pure in-memory fake — no real DNS, no real HTTP, no
real clock — so this suite runs deterministically offline. See
docs/BUILD_SPEC.md §6.3.
"""

import ipaddress
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

import pytest

from app.core.scope.budgets import BudgetTracker
from app.core.scope.context import RunContext
from app.core.scope.kill_switch import KillSwitch
from app.core.scope.models import Budgets, ResolvedAuthorization, RulesOfEngagement


class FakeDnsResolver:
    """A programmable resolver: hostname -> list[ip_address], or raises."""

    def __init__(self, table: dict[str, list[str]] | None = None) -> None:
        self.table: dict[str, list[ipaddress._BaseAddress]] = {
            host: [ipaddress.ip_address(ip) for ip in ips] for host, ips in (table or {}).items()
        }
        self.calls: list[str] = []

    def set(self, hostname: str, ips: Sequence[str]) -> None:
        self.table[hostname] = [ipaddress.ip_address(ip) for ip in ips]

    async def resolve(self, hostname: str) -> list[ipaddress._BaseAddress]:
        self.calls.append(hostname)
        if hostname not in self.table:
            raise LookupError(f"no fake DNS entry for {hostname!r}")
        return self.table[hostname]


class FakeClock:
    """An injectable clock so time-dependent checks (auth expiry, wall-clock
    budgets) are deterministic instead of racing the real clock."""

    def __init__(self, start: datetime | None = None) -> None:
        self._now = start or datetime(2026, 9, 18, tzinfo=UTC)
        self._monotonic = 0.0

    def now(self) -> datetime:
        return self._now

    def monotonic(self) -> float:
        return self._monotonic

    def advance(self, **kwargs: float) -> None:
        delta = timedelta(**kwargs)
        self._now += delta
        self._monotonic += delta.total_seconds()


def make_budgets(**overrides: object) -> Budgets:
    defaults: dict[str, object] = {
        "max_requests": 500,
        "max_concurrency": 3,
        "requests_per_second": 10.0,
        "max_tokens_sent": 100_000,
        "max_tokens_received": 200_000,
        "max_estimated_cost_usd": 5.00,
        "max_wall_clock_minutes": 30,
    }
    defaults.update(overrides)
    return Budgets(**defaults)  # type: ignore[arg-type]


def make_roe(**overrides: object) -> RulesOfEngagement:
    defaults: dict[str, object] = {
        "allowed_domains": ("ai.example.test", "*.ai.example.test"),
        "excluded_domains": (),
        "allowed_ip_ranges": (),
        "allowed_paths": (),
        "excluded_paths": (),
        "allowed_methods": ("GET", "POST"),
        "forbidden_headers": (),
        "budgets": make_budgets(),
        "safe_mode": True,
    }
    defaults.update(overrides)
    return RulesOfEngagement(**defaults)  # type: ignore[arg-type]


def make_authorization(*, clock: FakeClock, **overrides: object) -> ResolvedAuthorization:
    defaults: dict[str, object] = {
        "valid_from": clock.now() - timedelta(days=1),
        "valid_until": clock.now() + timedelta(days=6),
    }
    defaults.update(overrides)
    return ResolvedAuthorization(**defaults)  # type: ignore[arg-type]


def make_context(
    *,
    roe: RulesOfEngagement | None = None,
    authorization: ResolvedAuthorization | None = None,
    clock: FakeClock | None = None,
) -> RunContext:
    clock = clock or FakeClock()
    roe = roe or make_roe()
    authorization = authorization or make_authorization(clock=clock)
    budgets = BudgetTracker(roe.budgets, clock=clock.monotonic)
    return RunContext(
        roe=roe,
        authorization=authorization,
        budgets=budgets,
        kill_switch=KillSwitch(),
        clock=clock.now,
    )


@pytest.fixture
def fake_clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def fake_dns() -> FakeDnsResolver:
    # 203.0.113.0/24 is TEST-NET-3 (RFC 5737) — reserved for documentation,
    # and deliberately *not* in the engine's blocked-IP ranges, so these
    # resolve as an ordinary public target would.
    return FakeDnsResolver(
        {"ai.example.test": ["203.0.113.5"], "sub.ai.example.test": ["203.0.113.6"]}
    )
