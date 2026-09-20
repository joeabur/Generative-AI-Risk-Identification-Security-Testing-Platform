"""Reaching a notification destination through the one gated transport.

This is the same pattern as `app/core/assistant/egress.py`, for the same
reason: §28 says every outbound request goes through the scope-gated
transport, and a notification channel is exactly the sort of feature where
an exception gets introduced by accident because "it's only our own Slack".

The property that makes the grant safe is that the allowlist is derived from
a `Destination` that `policy.resolve_destination` already checked, and
contains that one host. There is no parameter here through which a caller
could widen it, so a notification context can never stand in for a target
authorization — and because `allowed_ip_ranges` is empty, the blocked-range
rules apply in full: a channel pointed at loopback, at an RFC1918 address or
at the cloud metadata service is refused.

Budgets are small and separate. A notification does not spend an
assessment's request budget, and a misconfigured channel that 500s in a loop
runs out of its own budget rather than an assessment's.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.core.integrations.contract import Destination
from app.core.scope.budgets import BudgetTracker
from app.core.scope.context import RunContext
from app.core.scope.kill_switch import KillSwitch
from app.core.scope.models import Budgets, ResolvedAuthorization, RulesOfEngagement

#: Short window, built per attempt: a stale context cannot be reused later to
#: post something nobody asked for.
DELIVERY_WINDOW = timedelta(minutes=5)

DELIVERY_BUDGETS = Budgets(
    max_requests=4,
    max_concurrency=1,
    requests_per_second=2.0,
    max_tokens_sent=0,
    max_tokens_received=0,
    max_estimated_cost_usd=0.0,
    max_wall_clock_minutes=2,
)


def notification_egress_context(destination: Destination) -> RunContext:
    """A scope context permitting one already-checked destination host."""
    now = datetime.now(UTC)
    roe = RulesOfEngagement(
        # Derived from the resolved destination, never from an argument a
        # caller chose. This is what keeps a channel from becoming a way to
        # reach a target, or an internal address, without authorization.
        allowed_domains=(destination.host,),
        excluded_domains=(),
        # Empty on purpose. Loopback, link-local, RFC1918 and the metadata
        # service stay blocked for a notification exactly as for a target.
        allowed_ip_ranges=(),
        allowed_paths=(),
        excluded_paths=(),
        allowed_methods=("POST",),
        forbidden_headers=(),
        budgets=DELIVERY_BUDGETS,
        safe_mode=True,
    )
    return RunContext(
        roe=roe,
        authorization=ResolvedAuthorization(
            valid_from=now - timedelta(minutes=1),
            valid_until=now + DELIVERY_WINDOW,
        ),
        budgets=BudgetTracker(DELIVERY_BUDGETS),
        kill_switch=KillSwitch(),
    )
