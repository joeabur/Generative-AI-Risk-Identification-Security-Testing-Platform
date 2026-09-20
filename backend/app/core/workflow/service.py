"""Running a workflow and recording every stage.

The thin, database-aware half. The decisions live in `plan.py` (pure) and
`result.py` (the gate); this module reads the target's configuration, drives the
stages in order, and writes what happened.

A workflow **does not gain capabilities**. It queues the same assessment run the
API queues, under the same authorization check and the same scope engine. If
that check refuses, the workflow is refused — recorded as `REFUSED` with the
reason, rather than failed, because "we were not authorized to do this" and "we
tried and it broke" are different facts about the same run.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import record_event
from app.core.gate.evaluate import load_config
from app.core.gate.model import GateConfig, GateConfigError
from app.core.workflow.contract import (
    Plan,
    Stage,
    Trigger,
    TriggerKind,
    WorkflowOutcome,
    WorkflowStatus,
)
from app.core.workflow.plan import TargetCapabilities, build_plan
from app.core.workflow.result import DEFAULT_GATE, decide
from app.models.api_spec import ApiSpec
from app.models.finding import Finding
from app.models.integration import NotificationChannel
from app.models.synthetic_account import SyntheticAccount
from app.models.target import Target
from app.models.vcs import VcsConnection
from app.models.workflow import Workflow, WorkflowRun


async def capabilities_for(
    db: AsyncSession, target: Target, *, trigger: Trigger
) -> TargetCapabilities:
    """Read what this target is actually configured for.

    Queried rather than inferred: a plan that guessed would produce a digest
    that did not describe what ran.
    """
    has_openapi = (
        await db.execute(select(ApiSpec.id).where(ApiSpec.target_id == target.id).limit(1))
    ).scalar_one_or_none() is not None
    has_accounts = (
        await db.execute(
            select(SyntheticAccount.id).where(SyntheticAccount.target_id == target.id).limit(1)
        )
    ).scalar_one_or_none() is not None
    has_channel = (
        await db.execute(
            select(NotificationChannel.id)
            .where(
                NotificationChannel.organization_id == target.organization_id,
                NotificationChannel.enabled.is_(True),
            )
            .limit(1)
        )
    ).scalar_one_or_none() is not None
    has_vcs = (
        await db.execute(
            select(VcsConnection.id)
            .where(
                VcsConnection.organization_id == target.organization_id,
                VcsConnection.enabled.is_(True),
            )
            .limit(1)
        )
    ).scalar_one_or_none() is not None

    return TargetCapabilities(
        kind=str(getattr(target.kind, "value", target.kind)),
        has_code_repo=bool(target.code_repo_ref),
        has_openapi=has_openapi,
        has_adapter=bool(target.adapter_kind),
        has_synthetic_accounts=has_accounts,
        can_publish_pr=has_vcs and trigger.pull_number is not None,
        has_notification_channel=has_channel,
    )


def gate_config_for(workflow: Workflow) -> GateConfig:
    """The workflow's gate, or the documented default.

    A malformed stored configuration is **not** silently replaced by the
    default: the gate's own rule is that a misconfigured gate must never report
    a pass, so it raises and the workflow is refused.
    """
    if not workflow.gate_config:
        return DEFAULT_GATE
    import json

    return load_config(json.dumps(workflow.gate_config))


async def findings_for(
    db: AsyncSession, organization_id: uuid.UUID, target_id: uuid.UUID
) -> Sequence[Finding]:
    result = await db.execute(
        select(Finding).where(
            Finding.organization_id == organization_id, Finding.target_id == target_id
        )
    )
    return list(result.scalars().all())


async def plan_for(db: AsyncSession, workflow: Workflow, trigger: Trigger) -> Plan:
    target = await db.get(Target, workflow.target_id)
    if target is None:
        raise ValueError("workflow target no longer exists")
    return build_plan(trigger, await capabilities_for(db, target, trigger=trigger))


async def start(
    db: AsyncSession,
    workflow: Workflow,
    trigger: Trigger,
) -> tuple[WorkflowRun, WorkflowOutcome]:
    """Record the trigger and the plan, and evaluate the result.

    Scan actions are *planned* here but executed by the assessment worker; this
    function records the plan, runs the stages it owns, and decides. Wiring the
    scan execution itself is done by the caller queueing an assessment run —
    which keeps one code path for "run an assessment" rather than two.
    """
    plan = await plan_for(db, workflow, trigger)
    outcome = WorkflowOutcome(status=WorkflowStatus.RUNNING, plan=plan)
    outcome.record(
        Stage.TRIGGER,
        ok=True,
        detail=f"{trigger.kind.value} by {trigger.actor}",
        **trigger.as_record(),
    )
    outcome.record(
        Stage.PLAN,
        ok=True,
        detail=f"{len(plan.will_run)} action(s) will run, "
        f"{len(plan.actions) - len(plan.will_run)} skipped",
        digest=plan.digest,
    )

    run = WorkflowRun(
        organization_id=workflow.organization_id,
        workflow_id=workflow.id,
        status=WorkflowStatus.RUNNING.value,
        trigger=trigger.as_record(),
        plan=plan.as_record(),
        plan_digest=plan.digest,
        stages=[item.as_record() for item in outcome.stages],
        evidence_refs=[],
        gate_reasons=[],
        gate_counts={},
        started_at=datetime.now(UTC),
    )
    db.add(run)
    await db.flush()
    return run, outcome


async def finish(
    db: AsyncSession,
    run: WorkflowRun,
    workflow: Workflow,
    outcome: WorkflowOutcome,
    *,
    evidence_refs: Sequence[str] = (),
    actions_detail: str = "",
) -> WorkflowOutcome:
    """Run the evidence and result stages, then persist everything."""
    outcome.record(
        Stage.ACTIONS,
        ok=True,
        detail=actions_detail or "actions completed",
    )
    outcome.evidence_refs = list(evidence_refs)
    outcome.record(
        Stage.EVIDENCE,
        ok=True,
        detail=f"{len(outcome.evidence_refs)} evidence bundle(s) sealed",
    )

    try:
        config = gate_config_for(workflow)
    except GateConfigError as exc:
        # A misconfigured gate must never report a pass.
        outcome.status = WorkflowStatus.REFUSED
        outcome.record(Stage.RESULT, ok=False, detail=f"gate configuration is invalid: {exc}")
        run.detail = f"gate configuration is invalid: {exc}"[:500]
        await _persist(db, run, outcome)
        return outcome

    findings = await findings_for(db, workflow.organization_id, workflow.target_id)
    decision = decide(findings, config)

    outcome.gate_passed = decision.passed
    outcome.gate_exit_code = int(decision.exit_code)
    outcome.gate_reasons = list(decision.reasons)
    outcome.gate_counts = dict(decision.counts)
    outcome.status = WorkflowStatus.COMPLETED
    outcome.record(
        Stage.RESULT,
        ok=decision.passed,
        detail="gate passed" if decision.passed else "; ".join(decision.reasons),
        blocking=len(decision.blocking),
        excluded=len(decision.excluded),
    )

    await _persist(db, run, outcome)
    await record_event(
        db,
        action="workflow.completed" if decision.passed else "workflow.gate_failed",
        resource_type="workflow_run",
        resource_id=str(run.id),
        result="allow" if decision.passed else "deny",
        organization_id=workflow.organization_id,
        metadata={
            "workflow": workflow.name,
            "trigger": run.trigger.get("kind"),
            "plan_digest": run.plan_digest,
            "gate_passed": decision.passed,
            "counts": dict(decision.counts),
        },
    )
    return outcome


async def _persist(db: AsyncSession, run: WorkflowRun, outcome: WorkflowOutcome) -> None:
    run.status = outcome.status.value
    run.stages = [item.as_record() for item in outcome.stages]
    run.evidence_refs = list(outcome.evidence_refs)
    run.gate_passed = outcome.gate_passed
    run.gate_exit_code = outcome.gate_exit_code
    run.gate_reasons = list(outcome.gate_reasons)
    run.gate_counts = dict(outcome.gate_counts)
    run.finished_at = datetime.now(UTC)
    await db.flush()


def trigger_from(
    workflow: Workflow,
    *,
    ref: str | None = None,
    commit: str | None = None,
    pull_number: int | None = None,
    actor: str = "system",
) -> Trigger:
    return Trigger(
        kind=TriggerKind(workflow.trigger_kind),
        organization_id=workflow.organization_id,
        target_id=workflow.target_id,
        ref=ref,
        commit=commit,
        pull_number=pull_number,
        actor=actor,
    )
