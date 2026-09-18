"""Promoting a run's results into persistent findings.

The DB bridge for `normalize.py`, kept separate so the computation stays
testable without a database.

The behaviour that matters is what happens on the *second* run: a finding
already known by fingerprint is not duplicated. Its sighting count, last
seen and last run are updated, and an operator's lifecycle decision is
preserved — re-running a scan must not reopen something a human marked as
accepted risk, or silently revert a triage.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.findings.normalize import build_finding
from app.core.probes.models import Severity
from app.core.risk.model import Environment, Exposure
from app.models.finding import Finding, FindingStatus, Stability
from app.models.scan_result import ScanResultRecord
from app.models.target import Target, TargetEnvironment

_ENVIRONMENTS = {
    TargetEnvironment.DEV: Environment.DEV,
    TargetEnvironment.TEST: Environment.TEST,
    TargetEnvironment.STAGING: Environment.STAGING,
    TargetEnvironment.PRODUCTION: Environment.PRODUCTION,
}


def exposure_for(target: Target) -> Exposure:
    """A conservative reading of how reachable a target is.

    Defaults to the *higher* exposure when unsure: under-stating reach
    produces a comfortable number and an unpleasant surprise, and the model
    should be wrong in the direction that gets a finding looked at.
    """
    base = (target.base_url or "").lower()
    internal = any(
        marker in base
        for marker in ("localhost", "127.0.0.1", ".internal", ".local", ".test", ".lab")
    )
    requires_auth = any(endpoint.requires_auth for endpoint in (target.surface_endpoints or []))

    if internal:
        return (
            Exposure.INTERNAL_AUTHENTICATED if requires_auth else Exposure.INTERNAL_UNAUTHENTICATED
        )
    return Exposure.INTERNET_AUTHENTICATED if requires_auth else Exposure.INTERNET_UNAUTHENTICATED


async def promote_run_results(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    run_id: uuid.UUID,
    target: Target,
) -> list[Finding]:
    """Turn this run's scan results into findings, deduplicated by fingerprint."""
    rows = (
        (await db.execute(select(ScanResultRecord).where(ScanResultRecord.run_id == run_id)))
        .scalars()
        .all()
    )

    exposure = exposure_for(target)
    environment = _ENVIRONMENTS[target.environment]
    now = datetime.now(UTC)
    promoted: list[Finding] = []

    for row in rows:
        # Informational rows are coverage notes and "not tested" markers.
        # Promoting them would put "this was not tested" into a findings
        # list as though it were a problem.
        if row.severity is Severity.INFORMATIONAL:
            continue

        draft = build_finding(row.to_scan_result(), exposure=exposure, environment=environment)
        existing = (
            await db.execute(
                select(Finding).where(
                    Finding.organization_id == organization_id,
                    Finding.fingerprint == draft.fingerprint,
                )
            )
        ).scalar_one_or_none()

        if existing is None:
            finding = Finding(
                organization_id=organization_id,
                target_id=target.id,
                fingerprint=draft.fingerprint,
                title=draft.title,
                category=draft.category,
                probe_id=draft.probe_id,
                probe_version=draft.probe_version,
                surface=draft.surface,
                severity=draft.severity,
                severity_rationale=draft.severity_rationale,
                confidence=draft.confidence,
                stability=Stability(draft.stability),
                risk_model=draft.risk.model,
                risk_score=draft.risk.value,
                risk_inputs=draft.risk.inputs.as_dict(),
                attack_success_rate=draft.attack_success_rate,
                control_success_rate=draft.control_success_rate,
                description=draft.description,
                impact=draft.impact,
                remediation=draft.remediation,
                evidence_ref=draft.evidence_ref,
                reproduction=list(draft.reproduction),
                mappings=draft.mappings,
                mapping_versions=draft.mapping_versions,
                status=FindingStatus.NEW,
                first_seen=now,
                last_seen=now,
                times_seen=1,
                first_run_id=run_id,
                last_run_id=run_id,
            )
            db.add(finding)
            promoted.append(finding)
            continue

        # Seen again. The measurement and score are refreshed because they
        # come from this run; the lifecycle status is not, because it came
        # from a person.
        existing.last_seen = now
        existing.last_run_id = run_id
        existing.times_seen += 1
        existing.severity = draft.severity
        existing.severity_rationale = draft.severity_rationale
        existing.risk_score = draft.risk.value
        existing.risk_inputs = draft.risk.inputs.as_dict()
        existing.attack_success_rate = draft.attack_success_rate
        existing.control_success_rate = draft.control_success_rate
        existing.probe_version = draft.probe_version

        # One exception to leaving the status alone: something marked
        # remediated that a later run still finds is not remediated, and
        # silently leaving it closed would be the most dangerous kind of
        # stale record.
        if existing.status in (FindingStatus.REMEDIATED, FindingStatus.CLOSED):
            existing.status = FindingStatus.CONFIRMED
            existing.status_note = (
                f"Reopened automatically: still present in run {run_id} after being "
                f"marked {existing.status.value}."
            )
        promoted.append(existing)

    await db.flush()
    return promoted
