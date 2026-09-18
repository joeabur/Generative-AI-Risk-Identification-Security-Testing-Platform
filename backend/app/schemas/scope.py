import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RulesOfEngagementRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target_id: uuid.UUID
    allowed_domains: list[str]
    excluded_domains: list[str]
    allowed_ip_ranges: list[str]
    allowed_paths: list[str]
    excluded_paths: list[str]
    allowed_methods: list[str]
    forbidden_headers: list[str]
    budgets: dict[str, Any]
    safe_mode: bool
    blackout_windows: list[dict[str, Any]]


class ScopeExplainRequest(BaseModel):
    method: str = Field(default="GET", min_length=1, max_length=16)
    url: str = Field(min_length=1)
    headers: dict[str, str] = Field(default_factory=dict)
    estimated_tokens_sent: int = 0
    estimated_tokens_received: int = 0
    estimated_cost_usd: float = 0.0


class ScopeExplainResponse(BaseModel):
    allowed: bool
    rule: str
    reason: str
