"""The one seam where a persisted `Target` (SQLAlchemy) meets the
DB-independent `RunContext` the scope engine operates on.

Kept out of `app/core/scope/` deliberately: every file in that package is
free of any SQLAlchemy/DB import, which is exactly what makes it trivially
unit-testable (docs/BUILD_SPEC.md §6, §22). This module is the bridge, not
part of the pure engine.
"""

from app.core.scope.budgets import BudgetTracker
from app.core.scope.context import RunContext
from app.core.scope.errors import RoEValidationError
from app.core.scope.kill_switch import KillSwitch
from app.core.scope.models import ResolvedAuthorization
from app.core.scope.resolve import resolve_authorization, resolve_rules_of_engagement
from app.models.target import Target


def build_run_context(target: Target) -> RunContext:
    """Resolve `target.authorization` and `target.rules_of_engagement` into
    a fresh `RunContext`. Raises `AuthorizationRequiredError` or
    `RoEValidationError` if either is missing or invalid — the same
    fail-closed refusal the scope engine itself enforces, just one step
    earlier, before any `RunContext` even exists.
    """
    authorization = resolve_authorization(
        ResolvedAuthorization(
            valid_from=target.authorization.valid_from,
            valid_until=target.authorization.valid_until,
        )
        if target.authorization is not None
        else None
    )

    if target.rules_of_engagement is None:
        raise RoEValidationError("No Rules of Engagement are configured for this target.")

    roe_row = target.rules_of_engagement
    roe = resolve_rules_of_engagement(
        {
            "allowed_domains": roe_row.allowed_domains,
            "excluded_domains": roe_row.excluded_domains,
            "allowed_ip_ranges": roe_row.allowed_ip_ranges,
            "allowed_paths": roe_row.allowed_paths,
            "excluded_paths": roe_row.excluded_paths,
            "allowed_methods": roe_row.allowed_methods,
            "forbidden_headers": roe_row.forbidden_headers,
            "budgets": roe_row.budgets,
            "safe_mode": roe_row.safe_mode,
            "blackout_windows": roe_row.blackout_windows,
        }
    )

    return RunContext(
        roe=roe,
        authorization=authorization,
        budgets=BudgetTracker(roe.budgets),
        kill_switch=KillSwitch(),
    )
