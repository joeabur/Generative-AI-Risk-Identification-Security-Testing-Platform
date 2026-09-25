"""Reaching a code host through the one gated transport.

Third instance of the same pattern (`assistant/egress.py`,
`integrations/egress.py`), and it earns its repetition: the allowlist is
derived from a `Destination` that `policy.resolve_destination` already checked,
holds that one API host, and cannot be widened by any caller. A code-host
connection therefore cannot be turned into a way to reach a target, an internal
service, or the cloud metadata endpoint.

`allowed_methods` is wider than the notification context's because the work is
read-then-write: `GET` to read a pull request's changed lines, `POST` to create
a check run and a review. It stops short of `PUT`, `PATCH` and `DELETE`, which
is what the GitHub API uses to merge a pull request, update a branch reference
or delete a file — the operations `contract.py` says this layer never performs.
The scope engine refuses them, so that promise is enforced rather than
asserted.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.core.scope.budgets import BudgetTracker
from app.core.scope.context import RunContext
from app.core.scope.kill_switch import KillSwitch
from app.core.scope.models import Budgets, ResolvedAuthorization, RulesOfEngagement
from app.core.vcs.contract import Destination

PUBLISH_WINDOW = timedelta(minutes=10)

#: One publish is a handful of requests: read the diff (paginated), create the
#: check run, post a review. Bounded so a paging bug stops rather than hammers
#: someone's API quota.
PUBLISH_BUDGETS = Budgets(
    max_requests=30,
    max_concurrency=2,
    requests_per_second=5.0,
    max_tokens_sent=0,
    max_tokens_received=0,
    max_estimated_cost_usd=0.0,
    max_wall_clock_minutes=5,
)


def vcs_egress_context(destination: Destination) -> RunContext:
    """A scope context permitting one already-checked code-host API host."""
    now = datetime.now(UTC)
    roe = RulesOfEngagement(
        allowed_domains=(destination.host,),
        excluded_domains=(),
        # Empty on purpose: a self-hosted code host on an internal address is
        # exactly the case where an operator must widen the rules deliberately,
        # not one this context should quietly permit.
        allowed_ip_ranges=(),
        allowed_paths=(),
        excluded_paths=(),
        # Read and create only. PUT/PATCH/DELETE — merge, update-ref, delete
        # file — are refused by the engine, not merely avoided by this code.
        allowed_methods=("GET", "POST"),
        forbidden_headers=(),
        budgets=PUBLISH_BUDGETS,
        safe_mode=True,
    )
    return RunContext(
        roe=roe,
        authorization=ResolvedAuthorization(
            valid_from=now - timedelta(minutes=1), valid_until=now + PUBLISH_WINDOW
        ),
        budgets=BudgetTracker(PUBLISH_BUDGETS),
        kill_switch=KillSwitch(),
    )
