"""Loading a gate configuration and reaching a verdict (docs/BUILD_SPEC.md §23).

The evaluation is deliberately verbose about what it *excluded*. A gate that
prints "failed: 3 findings" teaches people to bypass it; one that prints which
findings failed it, and which were skipped for being single-shot or
low-confidence or accepted until a date, is one they can argue with — and
arguing with it is how it stays switched on.
"""

from datetime import UTC, date, datetime
from typing import Any

import yaml

from app.core.gate.model import (
    DEFAULT_STABILITY,
    Exclusion,
    ExitCode,
    GateConfig,
    GateConfigError,
    GateDecision,
    GateFinding,
    Ignore,
    confidence_at_least,
    severity_at_least,
)
from app.core.probes.models import Confidence, Severity

# Statuses a human has already ruled on. Re-blocking a pipeline on a finding
# somebody accepted or marked a false positive would make the triage workflow
# pointless.
_SETTLED_STATUSES = frozenset({"false_positive", "accepted_risk", "closed"})

# Severity position, most severe first, for finding the fail_on threshold.
_SEVERITY_INDEX: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFORMATIONAL: 4,
}

MAX_CONFIG_BYTES = 256 * 1024


def load_config(raw: str) -> GateConfig:
    """Parse `security-gate.yaml`.

    Strict on purpose: an unknown key is an error rather than something to
    ignore. A typo'd `max_hihg: 0` that silently does nothing is exactly the
    failure this rule prevents, and it would leave a team believing they had a
    gate they did not have.
    """
    if len(raw.encode("utf-8", errors="ignore")) > MAX_CONFIG_BYTES:
        raise GateConfigError("security gate configuration is implausibly large")

    try:
        document = yaml.safe_load(raw) or {}
    except yaml.YAMLError as exc:
        raise GateConfigError(f"could not parse gate configuration: {exc}") from exc
    if not isinstance(document, dict):
        raise GateConfigError("gate configuration must be a mapping")

    section = document.get("security_gate", document)
    if not isinstance(section, dict):
        raise GateConfigError("`security_gate` must be a mapping")

    allowed = {
        "fail_on",
        "max_high",
        "max_medium",
        "min_confidence",
        "require_stability",
        "ignore",
    }
    unknown = sorted(set(section) - allowed)
    if unknown:
        raise GateConfigError(
            f"unknown gate setting(s): {', '.join(unknown)}. "
            f"Known settings: {', '.join(sorted(allowed))}"
        )

    return GateConfig(
        fail_on=_severities(section.get("fail_on")),
        # `in` rather than `.get`, because `max_high: null` has to mean "no
        # limit" and absence has to mean the default. Collapsing the two would
        # make the null in the documented example silently strict.
        max_high=_limit(section, "max_high", default=0),
        max_medium=_limit(section, "max_medium", default=5),
        min_confidence=_confidence(section.get("min_confidence")),
        require_stability=_stability(section.get("require_stability")),
        ignores=_ignores(section.get("ignore")),
    )


def evaluate(
    findings: list[GateFinding], config: GateConfig, *, today: date | None = None
) -> GateDecision:
    """Decide, and say why."""
    moment = today or datetime.now(UTC).date()
    blocking: list[GateFinding] = []
    excluded: list[Exclusion] = []
    counted: dict[Severity, int] = dict.fromkeys(Severity, 0)

    for finding in findings:
        reason = _exclusion_reason(finding, config, moment)
        if reason is not None:
            excluded.append(Exclusion(finding=finding, reason=reason))
            continue

        counted[finding.severity] += 1
        # Anything at or above the *least* severe entry in `fail_on`. A gate
        # configured with `[high]` that let a critical through would be
        # indefensible, and someone writing that list is saying "this bad and
        # worse", not "exactly this".
        if config.fail_on and severity_at_least(finding.severity, _floor(config.fail_on)):
            blocking.append(finding)

    reasons: list[str] = []
    if blocking:
        listed = ", ".join(sorted({item.severity.value for item in blocking}))
        floor = _floor(config.fail_on).value
        reasons.append(
            f"{len(blocking)} finding(s) at or above {floor} ({listed}) — fail_on is "
            f"{', '.join(severity.value for severity in config.fail_on)}"
        )

    if config.max_high is not None and counted[Severity.HIGH] > config.max_high:
        reasons.append(
            f"{counted[Severity.HIGH]} high finding(s) exceeds max_high={config.max_high}"
        )
    if config.max_medium is not None and counted[Severity.MEDIUM] > config.max_medium:
        reasons.append(
            f"{counted[Severity.MEDIUM]} medium finding(s) exceeds max_medium={config.max_medium}"
        )

    passed = not reasons
    return GateDecision(
        passed=passed,
        exit_code=ExitCode.PASS if passed else ExitCode.GATE_FAILED,
        blocking=sorted(blocking, key=lambda item: item.severity.value),
        excluded=excluded,
        reasons=reasons,
        counts={severity.value: count for severity, count in counted.items()},
    )


def _floor(fail_on: tuple[Severity, ...]) -> Severity:
    """The least severe entry in `fail_on` — the threshold the gate acts on."""
    return max(fail_on, key=lambda severity: _SEVERITY_INDEX[severity])


def _exclusion_reason(finding: GateFinding, config: GateConfig, today: date) -> str | None:
    if finding.status in _SETTLED_STATUSES:
        return f"status is {finding.status}: a human has already ruled on this"

    if finding.stability not in config.require_stability:
        # The §23 rule, stated where it acts.
        return (
            f"stability is {finding.stability}, which this gate does not act on. "
            "One observation is not a measurement, and a pipeline that fails on "
            "one fails arbitrarily."
        )

    if not confidence_at_least(finding.confidence, config.min_confidence):
        return (
            f"confidence is {finding.confidence.value}, below "
            f"min_confidence={config.min_confidence.value}"
        )

    ignore = config.ignore_for(finding.fingerprint, today)
    if ignore is not None:
        return f"ignored until {ignore.expires.isoformat()}: {ignore.reason}"

    return None


def _severities(value: Any) -> tuple[Severity, ...]:
    if value is None:
        return (Severity.CRITICAL, Severity.HIGH)
    if not isinstance(value, list):
        raise GateConfigError("fail_on must be a list of severities")
    out: list[Severity] = []
    for item in value:
        try:
            out.append(Severity(str(item).upper()))
        except ValueError as exc:
            raise GateConfigError(f"unknown severity in fail_on: {item!r}") from exc
    return tuple(out)


def _confidence(value: Any) -> Confidence:
    if value is None:
        return Confidence.MEDIUM
    try:
        return Confidence(str(value).upper())
    except ValueError as exc:
        raise GateConfigError(f"unknown min_confidence: {value!r}") from exc


def _stability(value: Any) -> tuple[str, ...]:
    if value is None:
        return DEFAULT_STABILITY
    if not isinstance(value, list):
        raise GateConfigError("require_stability must be a list")
    allowed = {"deterministic", "probabilistic", "single_shot"}
    out: list[str] = []
    for item in value:
        text = str(item).strip().lower()
        if text not in allowed:
            raise GateConfigError(
                f"unknown stability {item!r}; expected one of {', '.join(sorted(allowed))}"
            )
        out.append(text)
    return tuple(out)


def _limit(section: dict[str, Any], name: str, *, default: int) -> int | None:
    """The limit for `name`: absent means the default, explicit null means no
    limit, and anything else has to be a non-negative whole number."""
    if name not in section:
        return default
    value = section[name]
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise GateConfigError(f"{name} must be a whole number or null")
    if value < 0:
        raise GateConfigError(f"{name} cannot be negative")
    return value


def _ignores(value: Any) -> tuple[Ignore, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise GateConfigError("ignore must be a list")
    out: list[Ignore] = []
    for item in value:
        if not isinstance(item, dict):
            raise GateConfigError("each ignore entry must be a mapping")
        missing = sorted({"fingerprint", "reason", "expires"} - set(item))
        if missing:
            # All three are required: see `Ignore`. An exclusion without a
            # reason or an expiry is how a gate quietly stops covering things.
            raise GateConfigError(
                f"ignore entry is missing {', '.join(missing)}; all of fingerprint, "
                "reason and expires are required"
            )
        out.append(
            Ignore(
                fingerprint=str(item["fingerprint"]),
                reason=str(item["reason"]),
                expires=_date(item["expires"]),
            )
        )
    return tuple(out)


def _date(value: Any) -> date:
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value))
    except ValueError as exc:
        raise GateConfigError(f"expires must be an ISO date (YYYY-MM-DD), got {value!r}") from exc
