"""The wire format every probe, plugin and third-party adapter emits
(docs/BUILD_SPEC.md §11.1).

Deliberately smaller than the stored `Finding` of §11: a probe reports what
it observed and how confident it is, and the findings service (Phase 7) is
the only thing that promotes a `ScanResult` into a `Finding` by adding the
fingerprint, ASR aggregation across trials, risk score, mapping versions and
lifecycle state. Keeping that boundary here means a plugin author never has
to construct — or can never fake — a risk score.
"""

from dataclasses import dataclass, field
from enum import StrEnum


class Category(StrEnum):
    AI_SECURITY = "AI_SECURITY"
    API_SECURITY = "API_SECURITY"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    DESIGN = "DESIGN"


class Severity(StrEnum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(StrEnum):
    """`DESIGN_REVIEW` is what an analysis-mode probe reports.

    It exists so a spec-only observation can never be presented as though
    the behaviour was exercised against the target: §10 runs mass assignment
    in analysis mode under safe mode, and a reader must be able to tell that
    apart from a confirmed live result.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    DESIGN_REVIEW = "DESIGN_REVIEW"


@dataclass(frozen=True)
class ScanResult:
    id: str
    title: str
    category: Category
    severity: Severity
    confidence: Confidence
    endpoint: str
    description: str
    evidence: str
    impact: str
    remediation: str
    probe_id: str
    probe_version: str
    frameworks: tuple[str, ...] = ()
    # Ordered steps a reader can follow to see the same thing again (§27:
    # "every finding: ... reproduction steps"). Probes fill this from what
    # they actually sent, never from a template.
    reproduction: tuple[str, ...] = field(default=())
