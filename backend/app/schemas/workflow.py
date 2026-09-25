"""Workflow API shapes (docs/BUILD_SPEC.md §26 Phase 17).

The gate configuration is the only field here that carries real risk, and it is
handled the way the CLI gate handles it: validated on write through
`load_config`, so a malformed gate is rejected at the point somebody typed it
rather than at the point it was supposed to block a release. A gate that cannot
be parsed must never be read as "no gate".
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.gate.model import GateConfigError
from app.core.workflow.contract import TriggerKind


class WorkflowCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    target_id: uuid.UUID
    trigger_kind: TriggerKind = TriggerKind.REPOSITORY_CHANGE
    enabled: bool = True
    gate_config: dict[str, Any] | None = None

    @field_validator("gate_config")
    @classmethod
    def _gate_config_must_parse(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is None:
            return None
        from app.core.gate.evaluate import load_config

        try:
            load_config(json.dumps(value))
        except GateConfigError as exc:
            raise ValueError(f"gate configuration is invalid: {exc}") from exc
        return value


class WorkflowUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    enabled: bool | None = None
    gate_config: dict[str, Any] | None = None

    _gate_config_must_parse = field_validator("gate_config")(
        WorkflowCreate._gate_config_must_parse.__func__  # type: ignore[attr-defined]
    )


class WorkflowRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    target_id: uuid.UUID
    name: str
    trigger_kind: str
    enabled: bool
    gate_config: dict[str, Any] | None
    created_at: datetime


class WorkflowRunRequest(BaseModel):
    """What a caller may say about a trigger.

    Deliberately narrow. A caller cannot choose the plan, the actions, or the
    gate — those are derived from the workflow and the target's configuration,
    which is what makes the stored plan digest mean anything.
    """

    ref: str | None = Field(default=None, max_length=300)
    commit: str | None = Field(default=None, max_length=100)
    pull_number: int | None = Field(default=None, ge=1)


class WorkflowRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    workflow_id: uuid.UUID
    assessment_run_id: uuid.UUID | None
    status: str
    trigger: dict[str, Any]
    plan: dict[str, Any]
    plan_digest: str
    stages: list[dict[str, Any]]
    evidence_refs: list[str]
    gate_passed: bool | None
    gate_exit_code: int | None
    gate_reasons: list[str]
    gate_counts: dict[str, Any]
    started_at: datetime | None
    finished_at: datetime | None
    detail: str | None
    created_at: datetime
