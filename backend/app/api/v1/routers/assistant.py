"""AI assistant endpoints (Implementation Specification §8, §11).

Every route here produces or reads a **draft**. There is deliberately no
endpoint that applies a draft to a finding's real fields, changes a status,
starts a scan, or touches an authorization — those are not missing features,
they are the boundary (`docs/BUILD_SPEC.md` §4.5 row 7, §28).
"""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select

from app.api.v1.routers.runs import _load_run
from app.audit.service import record_event
from app.auth.dependencies import DbSession, require_membership
from app.core.assistant.autonomy import AutonomyError
from app.core.assistant.factory import build_ai_service
from app.core.assistant.service import AIService, Draft, FindingView
from app.core.config import get_settings
from app.models.ai_draft import AiDraft, DraftField
from app.models.organization import Membership, Role
from app.models.scan_result import ScanResultRecord
from app.schemas.assistant import AssistantStatus, DraftRead, DraftRequest

router = APIRouter(prefix="/organizations/{organization_id}/assistant", tags=["assistant"])


def get_ai_service() -> AIService:
    """Overridable dependency so tests inject a deterministic provider and
    never spend tokens (Implementation Specification §20)."""
    return build_ai_service(get_settings())


@router.get("/status", response_model=AssistantStatus)
async def assistant_status(
    organization_id: uuid.UUID,
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
    service: AIService = Depends(get_ai_service),  # noqa: B008
) -> AssistantStatus:
    """Whether the assistant is available, so a UI can say so rather than
    offering a control that will fail."""
    if not service.configured:
        return AssistantStatus(
            configured=False,
            autonomy_mode=service.mode.name,
            reason=(
                "No AI provider is configured, or the autonomy mode is OFF. Scanning, "
                "scoring, reporting and the CI gate are unaffected."
            ),
        )
    return AssistantStatus(configured=True, autonomy_mode=service.mode.name)


@router.post(
    "/runs/{run_id}/drafts",
    response_model=DraftRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_draft(
    organization_id: uuid.UUID,
    run_id: uuid.UUID,
    payload: DraftRequest,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ANALYST)),  # noqa: B008
    service: AIService = Depends(get_ai_service),  # noqa: B008
) -> DraftRead:
    """Generate a draft for a finding or for the run as a whole."""
    run = await _load_run(organization_id, run_id, db)

    result: ScanResultRecord | None = None
    if payload.scan_result_id is not None:
        result = (
            await db.execute(
                select(ScanResultRecord).where(
                    ScanResultRecord.id == payload.scan_result_id,
                    ScanResultRecord.run_id == run_id,
                )
            )
        ).scalar_one_or_none()
        if result is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Scan result not found")
    elif payload.field is not DraftField.RUN_SUMMARY:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"{payload.field.value} needs a scan_result_id",
        )

    try:
        draft = await _generate(service, payload.field, run_id, result, db)
    except AutonomyError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - a provider fault is not a server bug
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"AI provider unavailable: {exc}"
        ) from exc

    record = AiDraft(
        organization_id=organization_id,
        run_id=run.id,
        scan_result_id=result.id if result is not None else None,
        field=payload.field,
        content=draft.content,
        provider=draft.provider,
        model=draft.model,
        prompt_template_id=draft.prompt_template_id,
        prompt_template_version=draft.prompt_template_version,
        requested_by_user_id=membership.user_id,
    )
    db.add(record)
    await db.flush()

    await record_event(
        db,
        action="assistant.draft.create",
        resource_type="ai_draft",
        resource_id=str(record.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
        # Model, template and version, so "the AI drafted this" stays
        # traceable and reproducible (Addendum §6.3 item 4).
        metadata=draft.audit_metadata(),
    )
    await db.commit()

    return DraftRead.model_validate(record)


@router.get("/runs/{run_id}/drafts", response_model=list[DraftRead])
async def list_drafts(
    organization_id: uuid.UUID,
    run_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> list[DraftRead]:
    await _load_run(organization_id, run_id, db)
    rows = await db.execute(
        select(AiDraft)
        .where(AiDraft.run_id == run_id, AiDraft.organization_id == organization_id)
        .order_by(AiDraft.created_at)
    )
    return [DraftRead.model_validate(row) for row in rows.scalars().all()]


@router.post("/drafts/{draft_id}/accept", response_model=DraftRead)
async def accept_draft(
    organization_id: uuid.UUID,
    draft_id: uuid.UUID,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.SECURITY_ENGINEER)),  # noqa: B008
) -> DraftRead:
    """A human accepts a draft into the record.

    This is the only way AI-written text becomes report content, and it is
    an explicit act by a named person, recorded in the audit trail. Accepting
    is deliberately a higher privilege than requesting a draft: reading a
    suggestion is cheap, and putting it into the record is not.
    """
    draft = (
        await db.execute(
            select(AiDraft).where(
                AiDraft.id == draft_id, AiDraft.organization_id == organization_id
            )
        )
    ).scalar_one_or_none()
    if draft is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Draft not found")

    if draft.accepted_at is None:
        draft.accepted_at = datetime.now(UTC)
        draft.accepted_by_user_id = membership.user_id

        await record_event(
            db,
            action="assistant.draft.accept",
            resource_type="ai_draft",
            resource_id=str(draft.id),
            result="allow",
            organization_id=organization_id,
            user_id=membership.user_id,
            ip_address=request.client.host if request.client else None,
            metadata={"field": draft.field.value, "model": draft.model},
        )
    await db.commit()

    return DraftRead.model_validate(draft)


async def _generate(
    service: AIService,
    field: DraftField,
    run_id: uuid.UUID,
    result: ScanResultRecord | None,
    db: DbSession,
) -> Draft:
    if field is DraftField.RUN_SUMMARY:
        return await _summarise(service, run_id, db)

    assert result is not None  # guarded by the caller
    view = FindingView(
        probe_id=result.probe_id,
        title=result.title,
        endpoint=result.endpoint,
        severity=result.severity.value,
        description=result.description,
        evidence=result.evidence,
        remediation=result.remediation,
    )
    if field is DraftField.EXPLANATION:
        return await service.explain_finding(view)
    if field is DraftField.REMEDIATION:
        return await service.draft_remediation(view)
    return await service.draft_severity_rationale(view)


async def _summarise(service: AIService, run_id: uuid.UUID, db: DbSession) -> Draft:
    """Counts are computed here and passed in, never asked of the model.

    §14 requires the methodology and scope sections to be generated from
    data. A model asked to count would sometimes get it wrong, and a wrong
    number in an executive summary discredits the whole report.
    """
    rows = (
        (await db.execute(select(ScanResultRecord).where(ScanResultRecord.run_id == run_id)))
        .scalars()
        .all()
    )

    counts: dict[str, int] = {}
    titles: list[str] = []
    not_tested: list[str] = []
    for row in rows:
        counts[row.severity.value] = counts.get(row.severity.value, 0) + 1
        if row.title.startswith("Not tested:"):
            not_tested.append(row.title.removeprefix("Not tested:").strip())
        else:
            titles.append(row.title)

    return await service.summarise_run(
        target=str(run_id),
        checks=f"{len(rows)} result(s) recorded",
        severity_counts=counts,
        titles=titles,
        not_tested=not_tested,
    )
