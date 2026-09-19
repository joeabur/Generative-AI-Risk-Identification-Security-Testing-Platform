import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.models.target import TargetEnvironment, TargetKind


class DeclaredToolIn(BaseModel):
    """A tool the operator declares the agent can call.

    Declared, never discovered: docs/BUILD_SPEC.md §9 requires the tool
    surface to come from an operator, a manifest or an MCP adapter, because
    a permission graph inferred from a model's answers reads as
    authoritative and is fiction.
    """

    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=500)
    writes: bool = False
    irreversible: bool = False
    external: bool = False
    requires_confirmation: bool = False


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    environment: TargetEnvironment
    kind: TargetKind
    base_url: str = Field(min_length=1, max_length=2048)


class CodeScopeIn(BaseModel):
    """Which paths inside a checkout may be read.

    `allowed_paths` has no default: an unstated boundary is not a permissive
    one, and the engines refuse to run until it is declared
    (docs/BUILD_SPEC.md §4.5, §6.2).
    """

    allowed_paths: list[str] = Field(min_length=1, max_length=200)
    excluded_paths: list[str] = Field(default_factory=list, max_length=200)
    max_repo_size_mb: int = Field(default=500, ge=1, le=10_000)
    # Required before a remote repository can be cloned. Left empty, only a
    # local checkout is possible — which is the safe default.
    allowed_repo_hosts: list[str] = Field(default_factory=list, max_length=20)


class TargetCodeUpdate(BaseModel):
    repo_ref: str = Field(min_length=1, max_length=2048)
    languages: list[str] = Field(default_factory=list, max_length=20)
    build_manifest_paths: list[str] = Field(default_factory=list, max_length=50)
    code_scope: CodeScopeIn


class TargetAdapterUpdate(BaseModel):
    """Which adapter speaks to this target's chat surface, and how."""

    adapter_kind: Literal["chat_http", "openai_compatible"]
    adapter_config: dict[str, Any] = Field(default_factory=dict)
    declared_tools: list[DeclaredToolIn] = Field(default_factory=list, max_length=100)


class TargetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    environment: TargetEnvironment
    kind: TargetKind
    base_url: str
    adapter_kind: str | None
    adapter_config: dict[str, Any]
    code_repo_ref: str | None
    code_languages: list[str]
    code_build_manifest_paths: list[str]
    declared_tools: list[dict[str, Any]]
    has_authorization: bool
    has_rules_of_engagement: bool
    created_at: datetime
