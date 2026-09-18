"""Stored probe output (docs/BUILD_SPEC.md §11.1).

Deliberately the *wire* shape, not the `Finding` of §11. Promoting these
into findings — fingerprinting, aggregating trials into an attack success
rate, risk scoring, mapping versions and lifecycle — is the findings
service's job in Phase 7, and keeping the raw probe output as its own table
means that promotion can be re-run and corrected without re-scanning the
target.
"""

import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import BigInteger, Enum, ForeignKey, Identity, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.core.probes.models import Category, Confidence, Severity
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.assessment_run import AssessmentRun


class ScanResultRecord(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "scan_results"

    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessment_runs.id", ondelete="CASCADE"), nullable=False
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    seq: Mapped[int] = mapped_column(BigInteger, Identity(), nullable=False, unique=True)

    result_code: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    category: Mapped[Category] = mapped_column(
        Enum(Category, name="scan_result_category_enum"), nullable=False
    )
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="scan_result_severity_enum"), nullable=False
    )
    confidence: Mapped[Confidence] = mapped_column(
        Enum(Confidence, name="scan_result_confidence_enum"), nullable=False
    )
    endpoint: Mapped[str] = mapped_column(String(2048), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[str] = mapped_column(Text, nullable=False)
    impact: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    probe_id: Mapped[str] = mapped_column(String(200), nullable=False)
    probe_version: Mapped[str] = mapped_column(String(50), nullable=False)
    frameworks: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    reproduction: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    # Set by engines that can compute a stable identity (rule + path + code
    # span). Nullable because a dynamic probe's fingerprint is the findings
    # service's job, and a guessed one would be worse than none.
    fingerprint: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)

    run: Mapped["AssessmentRun"] = relationship(back_populates="scan_results")
