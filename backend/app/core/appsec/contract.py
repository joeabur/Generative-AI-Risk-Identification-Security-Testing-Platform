"""The AppSec engine contract (docs/BUILD_SPEC.md §26 Phase 14).

An engine reads files from a resolved `Workspace` and emits the same
`ScanResult` wire shape every other engine on this platform emits. It does
not invent identifiers, does not reach the network except as declared, and
reports plainly when its tool is absent rather than returning nothing and
letting silence read as a clean result.
"""

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

from app.core.appsec.workspace import Workspace
from app.core.probes.models import Category, Confidence, ScanResult, Severity


class Pillar(StrEnum):
    SAST = "sast"
    SCA = "sca"
    SECRETS = "secrets"
    IAC = "iac"


@dataclass(frozen=True)
class EngineMeta:
    id: str
    version: str
    name: str
    pillar: Pillar
    tool: str
    description: str


@runtime_checkable
class AppSecEngine(Protocol):
    meta: EngineMeta

    def applies_to(self, workspace: Workspace) -> bool: ...

    async def run(self, workspace: Workspace) -> list[ScanResult]: ...


# Whitespace and quoting change constantly and mean nothing to a
# fingerprint; what identifies a piece of code is its token shape.
_NORMALIZE = re.compile(r"\s+")


def code_span_signature(snippet: str) -> str:
    """A stable signature for a span of code.

    Deliberately not the line number. §4.1 of the addendum is explicit about
    why: line numbers drift on unrelated edits, so fingerprinting on them
    would split one long-lived issue into a new finding on every commit that
    touched the file above it, and the §11 fingerprint-stability guarantee
    would be worthless.
    """
    normalized = _NORMALIZE.sub(" ", snippet.strip())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def finding_fingerprint(*, rule_id: str, relative_path: str, snippet: str) -> str:
    """rule id + normalized path + code-span signature (Addendum §4.1)."""
    material = f"{rule_id}|{relative_path}|{code_span_signature(snippet)}"
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def tool_unavailable(meta: EngineMeta, reason: str) -> ScanResult:
    """The result an engine emits when its tool could not run.

    §15 requires graceful degradation, and §14 requires a report to state
    what it did not cover. Those combine to this: a missing scanner produces
    a visible gap, never an empty result set that reads as "nothing found".
    """
    return ScanResult(
        id="AEGIS-APPSEC-000",
        title=f"Not tested: {meta.name}",
        category=Category.INFRASTRUCTURE,
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.DESIGN_REVIEW,
        endpoint=meta.pillar.value,
        description=(
            f"The {meta.pillar.value.upper()} engine did not run, so this assessment "
            f"says nothing about what {meta.tool} would have found."
        ),
        evidence=reason,
        impact="Unknown — the scan did not run, which is not the same as it passing.",
        remediation=(
            f"Install {meta.tool} on the worker and re-run, or record this pillar as "
            "out of scope for the engagement."
        ),
        probe_id=meta.id,
        probe_version=meta.version,
    )


def severity_from(label: str, default: Severity = Severity.MEDIUM) -> Severity:
    """Map a tool's own severity word onto ours, conservatively.

    An unrecognised label becomes the default rather than the lowest
    severity: a finding whose severity we could not read is not evidence
    that it is unimportant.
    """
    normalized = label.strip().upper()
    return {
        "CRITICAL": Severity.CRITICAL,
        "ERROR": Severity.HIGH,
        "HIGH": Severity.HIGH,
        "WARNING": Severity.MEDIUM,
        "MEDIUM": Severity.MEDIUM,
        "MODERATE": Severity.MEDIUM,
        "NOTE": Severity.LOW,
        "LOW": Severity.LOW,
        "INFO": Severity.INFORMATIONAL,
        "INFORMATIONAL": Severity.INFORMATIONAL,
        "UNKNOWN": default,
    }.get(normalized, default)
