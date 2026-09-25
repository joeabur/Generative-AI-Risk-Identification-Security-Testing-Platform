"""Turns raw input (a possibly-absent Authorization row, a raw RoE dict) into
the validated, pure domain types the engine operates on — the last chance to
refuse a run before it starts, per docs/BUILD_SPEC.md §6.1 ("resolve
authorization -> expired/absent -> ABORT RUN", "resolve RoE -> unparseable
-> ABORT RUN").
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from app.core.scope.errors import AuthorizationRequiredError, RoEValidationError
from app.core.scope.models import BlackoutWindow, Budgets, ResolvedAuthorization, RulesOfEngagement


def resolve_authorization(authorization: ResolvedAuthorization | None) -> ResolvedAuthorization:
    if authorization is None:
        raise AuthorizationRequiredError(
            "No authorization record is on file for this target. Refusing to run."
        )
    return authorization


class _BudgetsSchema(BaseModel):
    max_requests: int = Field(gt=0)
    max_concurrency: int = Field(gt=0)
    requests_per_second: float = Field(gt=0)
    max_tokens_sent: int = Field(gt=0)
    max_tokens_received: int = Field(gt=0)
    max_estimated_cost_usd: float = Field(gt=0)
    max_wall_clock_minutes: int = Field(gt=0)


class _BlackoutWindowSchema(BaseModel):
    starts_at: datetime
    ends_at: datetime


class _RulesOfEngagementSchema(BaseModel):
    allowed_domains: list[str] = Field(default_factory=list)
    excluded_domains: list[str] = Field(default_factory=list)
    allowed_ip_ranges: list[str] = Field(default_factory=list)
    allowed_paths: list[str] = Field(default_factory=list)
    excluded_paths: list[str] = Field(default_factory=list)
    allowed_methods: list[str] = Field(default_factory=lambda: ["GET"])
    forbidden_headers: list[str] = Field(default_factory=list)
    budgets: _BudgetsSchema
    safe_mode: bool = True
    allow_state_mutation: bool = False
    blackout_windows: list[_BlackoutWindowSchema] = Field(default_factory=list)


def resolve_rules_of_engagement(raw: dict[str, Any]) -> RulesOfEngagement:
    try:
        parsed = _RulesOfEngagementSchema.model_validate(raw)
    except ValidationError as exc:
        raise RoEValidationError(f"Rules of Engagement failed validation: {exc}") from exc

    return RulesOfEngagement(
        allowed_domains=tuple(parsed.allowed_domains),
        excluded_domains=tuple(parsed.excluded_domains),
        allowed_ip_ranges=tuple(parsed.allowed_ip_ranges),
        allowed_paths=tuple(parsed.allowed_paths),
        excluded_paths=tuple(parsed.excluded_paths),
        allowed_methods=tuple(m.upper() for m in parsed.allowed_methods),
        forbidden_headers=tuple(parsed.forbidden_headers),
        budgets=Budgets(
            max_requests=parsed.budgets.max_requests,
            max_concurrency=parsed.budgets.max_concurrency,
            requests_per_second=parsed.budgets.requests_per_second,
            max_tokens_sent=parsed.budgets.max_tokens_sent,
            max_tokens_received=parsed.budgets.max_tokens_received,
            max_estimated_cost_usd=parsed.budgets.max_estimated_cost_usd,
            max_wall_clock_minutes=parsed.budgets.max_wall_clock_minutes,
        ),
        safe_mode=parsed.safe_mode,
        allow_state_mutation=parsed.allow_state_mutation,
        blackout_windows=tuple(
            BlackoutWindow(starts_at=w.starts_at, ends_at=w.ends_at)
            for w in parsed.blackout_windows
        ),
    )
