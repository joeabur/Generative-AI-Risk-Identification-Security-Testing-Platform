"""Findings (docs/BUILD_SPEC.md §11).

Read and triage. A finding's severity, risk score and measurement are
computed from evidence and are not editable here — a severity someone typed
over would no longer match its rationale, and the pair losing sync is how a
report stops being trustworthy. What a human decides is the **status**, and
that is what these endpoints change.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select

from app.audit.service import record_event
from app.auth.dependencies import DbSession, require_membership
from app.core.probes.models import Severity
from app.models.finding import ALLOWED_TRANSITIONS, Finding, FindingStatus
from app.models.organization import Membership, Role
from app.schemas.finding import FindingRead, FindingTransition

router = APIRouter(prefix="/organizations/{organization_id}/findings", tags=["findings"])


@router.get("", response_model=list[FindingRead])
async def list_findings(
    organization_id: uuid.UUID,
    db: DbSession,
    severity: Severity | None = None,
    finding_status: FindingStatus | None = None,
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> list[FindingRead]:
    query = select(Finding).where(Finding.organization_id == organization_id)
    if severity is not None:
        query = query.where(Finding.severity == severity)
    if finding_status is not None:
        query = query.where(Finding.status == finding_status)

    rows = await db.execute(query.order_by(Finding.risk_score.desc(), Finding.last_seen.desc()))
    return [FindingRead.model_validate(row) for row in rows.scalars().all()]


@router.get("/{finding_id}", response_model=FindingRead)
async def get_finding(
    organization_id: uuid.UUID,
    finding_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> FindingRead:
    return FindingRead.model_validate(await _load(organization_id, finding_id, db))


@router.post("/{finding_id}/status", response_model=FindingRead)
async def transition_finding(
    organization_id: uuid.UUID,
    finding_id: uuid.UUID,
    payload: FindingTransition,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ANALYST)),  # noqa: B008
) -> FindingRead:
    """Move a finding through its lifecycle.

    Transitions are restricted so a finding cannot jump from `new` to
    `closed` without passing through a state that records why — which is
    what makes a closed finding auditable months later.
    """
    finding = await _load(organization_id, finding_id, db)

    if payload.status != finding.status:
        allowed = ALLOWED_TRANSITIONS.get(finding.status, frozenset())
        if payload.status not in allowed:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                detail=(
                    f"cannot move a finding from {finding.status.value} to "
                    f"{payload.status.value}; allowed: "
                    f"{', '.join(sorted(item.value for item in allowed)) or 'none'}"
                ),
            )
        finding.status = payload.status
        finding.status_note = payload.note
        finding.status_changed_by_user_id = membership.user_id

        await record_event(
            db,
            action="finding.status.change",
            resource_type="finding",
            resource_id=str(finding.id),
            result="allow",
            organization_id=organization_id,
            user_id=membership.user_id,
            ip_address=request.client.host if request.client else None,
            metadata={"status": payload.status.value, "fingerprint": finding.fingerprint},
        )
    await db.commit()

    return FindingRead.model_validate(finding)


async def _load(organization_id: uuid.UUID, finding_id: uuid.UUID, db: DbSession) -> Finding:
    finding = (
        await db.execute(
            select(Finding).where(
                Finding.id == finding_id, Finding.organization_id == organization_id
            )
        )
    ).scalar_one_or_none()
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return finding
