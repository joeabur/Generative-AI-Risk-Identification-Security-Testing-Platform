"""AI-drafted text, stored beside a finding and never over it
(Implementation Specification §10; Addendum v2.1 §6.2).

The whole point of this table is separation. A draft lives here, with the
model and prompt template that produced it recorded alongside; the scan
result's own fields are untouched. A draft becomes report text only when a
human accepts it, and the acceptance records who.

That is what makes "the AI drafted this remediation" answerable later, and
what stops a model's output from quietly becoming the record.
"""

import uuid
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.scan_result import ScanResultRecord


class DraftField(StrEnum):
    """Which field a draft is a candidate for.

    A closed set: a draft cannot be proposed for a field nobody decided was
    draftable, which keeps `severity`, `status` and the measurement fields
    permanently out of reach.
    """

    EXPLANATION = "explanation"
    REMEDIATION = "remediation"
    SEVERITY_RATIONALE = "severity_rationale"
    RUN_SUMMARY = "run_summary"


class AiDraft(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "ai_drafts"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessment_runs.id", ondelete="CASCADE"), nullable=False
    )
    # Null for a run-level draft such as an executive summary.
    scan_result_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_results.id", ondelete="CASCADE"), nullable=True
    )

    field: Mapped[DraftField] = mapped_column(
        Enum(DraftField, name="ai_draft_field_enum"), nullable=False
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)

    # Provenance, so a drafted artifact is always traceable to the model and
    # template that produced it (§6.3 item 4).
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    model: Mapped[str] = mapped_column(String(200), nullable=False)
    prompt_template_id: Mapped[str] = mapped_column(String(200), nullable=False)
    prompt_template_version: Mapped[str] = mapped_column(String(50), nullable=False)

    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    # Null until a human accepts it. Until then this text appears in no
    # report and no finding.
    accepted_at: Mapped["datetime | None"] = mapped_column(DateTime(timezone=True), nullable=True)
    accepted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    scan_result: Mapped["ScanResultRecord | None"] = relationship()

    @property
    def accepted(self) -> bool:
        return self.accepted_at is not None
