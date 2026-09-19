"""Assembling a `ReportData` from a persisted run.

The DB bridge for the reporting package. Everything factual is read from
what the run recorded — counts, digests, coverage markers — rather than
recomputed or described, so a report cannot claim something the run did not
establish.
"""

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.measure.asr import DEFAULT_RULE
from app.core.probes.models import Severity
from app.core.reporting.model import (
    SEVERITY_ORDER,
    NotTested,
    ReportData,
    ReportFinding,
    RetestRecord,
)
from app.core.risk.publish import render_markdown as render_risk_tables
from app.models.ai_draft import AiDraft
from app.models.assessment_run import TERMINAL_STATUSES, AssessmentRun, RunKind
from app.models.finding import Finding
from app.models.retest import RetestResult
from app.models.scan_result import ScanResultRecord
from app.models.target import Target

TOOL_VERSION = "0.1.0"

# Severity order as a lookup, for sorting rows that carry severity as a string.
SEVERITY_ORDER_INDEX = {severity.value: index for index, severity in enumerate(SEVERITY_ORDER)}

# Nothing here imports `app.core.assistant`, and a boundary test enforces it:
# the platform has to work with the AI layer absent, so reporting reads which
# sections a draft contributed from the `ai_drafts` rows and never from the
# assistant's own modules. An earlier draft of this file imported the
# assistant's evidence delimiters to strip them from drafted text; stripping
# a prompt artefact is the assistant's job at the point it stores a draft,
# not reporting's at the point it renders one.


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _report_finding(finding: Finding) -> ReportFinding:
    return ReportFinding(
        id=str(finding.id),
        fingerprint=finding.fingerprint,
        title=finding.title,
        category=finding.category.value,
        severity=finding.severity.value,
        severity_rationale=finding.severity_rationale,
        confidence=finding.confidence.value,
        stability=finding.stability.value,
        risk_model=finding.risk_model,
        risk_score=finding.risk_score,
        risk_inputs=dict(finding.risk_inputs or {}),
        surface=finding.surface,
        probe_id=finding.probe_id,
        probe_version=finding.probe_version,
        description=finding.description,
        impact=finding.impact,
        remediation=finding.remediation,
        reproduction=[str(step) for step in (finding.reproduction or [])],
        mappings=dict(finding.mappings or {}),
        mapping_versions=dict(finding.mapping_versions or {}),
        attack_success_rate=finding.attack_success_rate,
        control_success_rate=finding.control_success_rate,
        evidence_ref=finding.evidence_ref,
        status=finding.status.value,
        first_seen=finding.first_seen.isoformat(),
        last_seen=finding.last_seen.isoformat(),
        times_seen=finding.times_seen,
    )


def _not_tested_from(results: list[ScanResultRecord]) -> list[NotTested]:
    """Coverage gaps, taken from the engines' own markers.

    Reading them from the results rather than assembling a list by hand is
    what keeps §14's coverage honesty true over time: a section someone has
    to remember to update is a section that goes stale.
    """
    gaps: list[NotTested] = []
    for row in results:
        if row.severity is not Severity.INFORMATIONAL:
            continue
        if not row.title.startswith("Not tested:"):
            continue
        gaps.append(
            NotTested(
                area=row.title.removeprefix("Not tested:").strip(),
                reason=row.evidence.strip().splitlines()[0] if row.evidence else row.description,
                probe_id=row.probe_id,
            )
        )
    return gaps


def _judge_status(results: list[ScanResultRecord]) -> str:
    """What the run recorded about judging, verbatim where it exists."""
    for row in results:
        if row.result_code == "AEGIS-AI-900":
            first = row.evidence.strip().splitlines()
            if first:
                return first[0]
    return "Judge: not used in this run; all detections are deterministic or structural."


def _permission_graph(results: list[ScanResultRecord]) -> str | None:
    for row in results:
        if row.result_code == "AEGIS-AI-030" and "```mermaid" in row.evidence:
            return row.evidence.split("```mermaid", 1)[1].split("```", 1)[0].strip()
    return None


async def build_report(db: AsyncSession, *, run: AssessmentRun, target: Target) -> ReportData:
    """Everything a report needs, read from what the run recorded."""
    results = list(
        (await db.execute(select(ScanResultRecord).where(ScanResultRecord.run_id == run.id)))
        .scalars()
        .all()
    )
    findings = list(
        (
            await db.execute(
                select(Finding)
                .where(
                    Finding.organization_id == run.organization_id,
                    Finding.last_run_id == run.id,
                )
                .order_by(Finding.risk_score.desc())
            )
        )
        .scalars()
        .all()
    )
    accepted_drafts = list(
        (
            await db.execute(
                select(AiDraft).where(AiDraft.run_id == run.id, AiDraft.accepted_at.is_not(None))
            )
        )
        .scalars()
        .all()
    )

    authorization = target.authorization
    roe = target.rules_of_engagement

    limitations: list[str] = []
    if run.status not in TERMINAL_STATUSES:
        limitations.append(
            f"The run is still {run.status.value}: this report covers "
            f"{run.checks_completed} of {run.checks_total} checks and will change."
        )
    if run.halted_reason:
        limitations.append(f"The run stopped early: {run.halted_reason}.")
    if run.requests_blocked:
        limitations.append(
            f"{run.requests_blocked} request(s) were refused by the scope engine, so "
            "the surfaces they targeted were not exercised."
        )
    if not target.adapter_kind:
        limitations.append(
            "No conversational adapter was configured, so the AI security engine did "
            "not run against this target."
        )
    if not target.code_repo_ref:
        limitations.append(
            "No source repository was configured, so SAST, SCA, secret scanning and "
            "IaC analysis did not run against this target."
        )

    # A retest's verdicts, joined to their findings for the titles a reader
    # needs. Ordered by severity at baseline so the worst thing that is still
    # there is the first thing read.
    retests: list[RetestRecord] = []
    if run.kind is RunKind.RETEST:
        rows = list(
            (
                await db.execute(
                    select(RetestResult, Finding)
                    .join(Finding, Finding.id == RetestResult.finding_id)
                    .where(RetestResult.run_id == run.id)
                )
            ).all()
        )
        retests = sorted(
            (
                RetestRecord(
                    fingerprint=row.RetestResult.fingerprint,
                    title=row.Finding.title,
                    severity=row.Finding.severity.value,
                    verdict=row.RetestResult.verdict.value,
                    before_evidence_ref=row.RetestResult.before_evidence_ref,
                    after_evidence_ref=row.RetestResult.after_evidence_ref,
                    detail=row.RetestResult.detail,
                )
                for row in rows
            ),
            key=lambda record: SEVERITY_ORDER_INDEX.get(record.severity, 99),
        )

    return ReportData(
        organization=str(run.organization_id),
        target_name=target.name,
        target_kind=target.kind.value,
        target_environment=target.environment.value,
        target_base_url=target.base_url,
        run_id=str(run.id),
        generated_at=datetime.now(UTC),
        tool_version=TOOL_VERSION,
        authorization_reference=authorization.reference if authorization else None,
        authorization_by=(
            f"{authorization.authorized_by_name} ({authorization.authorized_by_role})"
            if authorization
            else None
        ),
        authorization_valid_from=_iso(authorization.valid_from) if authorization else None,
        authorization_valid_until=_iso(authorization.valid_until) if authorization else None,
        # Pinned at run start, so a later edit cannot rewrite the record.
        authorization_digest=run.authorization_digest,
        roe_digest=run.roe_digest,
        excluded_domains=[str(item) for item in (roe.excluded_domains if roe else [])],
        excluded_paths=[str(item) for item in (roe.excluded_paths if roe else [])],
        safe_mode=run.safe_mode,
        decision_rule=DEFAULT_RULE,
        judge_status=_judge_status(results),
        limitations=limitations,
        adapters=[target.adapter_kind] if target.adapter_kind else [],
        endpoints=[
            f"{endpoint.method} {endpoint.path}"
            for endpoint in (target.surface_endpoints or [])
            if endpoint.enabled
        ],
        declared_tools=[
            str(tool.get("name", "")) for tool in (target.declared_tools or []) if tool
        ],
        permission_graph=_permission_graph(results),
        findings=[_report_finding(finding) for finding in findings],
        not_tested=_not_tested_from(results),
        is_retest=run.kind is RunKind.RETEST,
        retests=retests,
        checks_completed=run.checks_completed,
        checks_total=run.checks_total,
        requests_blocked=run.requests_blocked,
        halted_reason=run.halted_reason,
        risk_model_tables=render_risk_tables(),
        tool_versions={"aegis": TOOL_VERSION},
        ai_drafted_sections=sorted({draft.field.value for draft in accepted_drafts}),
    )


def to_canonical_json(report: ReportData) -> str:
    """The canonical JSON rendering (§14).

    Sorted keys and a stable shape so two generations of the same report are
    byte-identical apart from the timestamp — which is what makes a golden
    snapshot test meaningful.
    """
    payload: dict[str, Any] = {
        "schema": "aegis.report/v1",
        "tool": {"name": "Aegis AI Security", "version": report.tool_version},
        "generated_at": report.generated_at.isoformat(),
        "target": {
            "name": report.target_name,
            "kind": report.target_kind,
            "environment": report.target_environment,
            "base_url": report.target_base_url,
        },
        "run": {
            "id": report.run_id,
            "checks_completed": report.checks_completed,
            "checks_total": report.checks_total,
            "requests_blocked": report.requests_blocked,
            "halted_reason": report.halted_reason,
            "safe_mode": report.safe_mode,
        },
        "authorization": {
            "reference": report.authorization_reference,
            "authorized_by": report.authorization_by,
            "valid_from": report.authorization_valid_from,
            "valid_until": report.authorization_valid_until,
            "digest": report.authorization_digest,
            "roe_digest": report.roe_digest,
            "excluded_domains": report.excluded_domains,
            "excluded_paths": report.excluded_paths,
        },
        "methodology": {
            "trials_per_probe": report.trials_per_probe,
            "decision_rule": report.decision_rule,
            "judge": report.judge_status,
            "limitations": report.limitations,
            "ai_drafted_sections": report.ai_drafted_sections,
        },
        "surface": {
            "adapters": report.adapters,
            "endpoints": report.endpoints,
            "declared_tools": report.declared_tools,
        },
        "risk_summary": report.severity_counts(),
        "findings": [
            {
                "fingerprint": finding.fingerprint,
                "title": finding.title,
                "category": finding.category,
                "severity": finding.severity,
                "severity_rationale": finding.severity_rationale,
                "confidence": finding.confidence,
                "stability": finding.stability,
                "risk": {
                    "model": finding.risk_model,
                    "score": finding.risk_score,
                    "inputs": finding.risk_inputs,
                },
                "attack_success_rate": finding.attack_success_rate,
                "control_success_rate": finding.control_success_rate,
                "surface": finding.surface,
                "probe": {"id": finding.probe_id, "version": finding.probe_version},
                "description": finding.description,
                "impact": finding.impact,
                "remediation": finding.remediation,
                "reproduction": finding.reproduction,
                "mappings": finding.mappings,
                "mapping_versions": finding.mapping_versions,
                "evidence_ref": finding.evidence_ref,
                "status": finding.status,
                "first_seen": finding.first_seen,
                "last_seen": finding.last_seen,
                "times_seen": finding.times_seen,
            }
            for finding in report.findings
        ],
        "retest": {
            "is_retest": report.is_retest,
            "results": [
                {
                    "fingerprint": record.fingerprint,
                    "title": record.title,
                    "severity": record.severity,
                    "verdict": record.verdict,
                    "before_evidence_ref": record.before_evidence_ref,
                    "after_evidence_ref": record.after_evidence_ref,
                    "detail": record.detail,
                }
                for record in report.retests
            ],
        },
        "coverage": {
            "reported_against": report.frameworks_covered(),
            "not_tested": [
                {"area": item.area, "reason": item.reason, "probe_id": item.probe_id}
                for item in report.not_tested
            ],
        },
    }
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def report_filename(run_id: uuid.UUID, template: str, extension: str) -> str:
    return f"aegis-report-{run_id}-{template}.{extension}"
