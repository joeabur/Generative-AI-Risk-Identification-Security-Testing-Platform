"""Runs an AI probe's plan as trials and measures the result
(docs/BUILD_SPEC.md §7.1, §9).

Every AI probe goes through here, which is what makes the determinism
claims uniform: no probe can decide for itself that one attempt was enough,
skip its control, or apply a softer rule than the one printed in the report.
"""

from dataclasses import dataclass

from app.core.measure.asr import DEFAULT_RULE, Measurement, measure
from app.core.probes.ai.contract import (
    AiProbe,
    AiProbeTarget,
    Ask,
    Attempt,
    ProbeOutcome,
    TrialRecord,
    new_canary,
)
from app.core.probes.models import ScanResult
from app.core.redaction.secrets import redact
from app.core.scope.context import RunContext

# Keeps a single probe from spending a whole run's budget on trials.
MAX_TRIALS = 20
MAX_RESPONSE_CHARS = 2000


@dataclass(frozen=True)
class TrialBudget:
    """Bounds on how much of a run one probe may spend."""

    trials: int = 5

    def resolve(self, requested: int | None) -> int:
        return max(1, min(requested or self.trials, MAX_TRIALS))


async def run_ai_probe(
    probe: AiProbe,
    target: AiProbeTarget,
    ctx: RunContext,
    ask: Ask,
    *,
    canary: str | None = None,
) -> list[ScanResult]:
    """Execute one probe's plan and hand it a measured outcome to report on.

    Controls run first. If the target already produces the marker without
    any adversarial component — because it echoes input, or because the
    prompt itself is enough — the attack cannot clear the bar, and finding
    that out first means not spending trials on a comparison that cannot
    produce a finding.
    """
    if not probe.applies_to(target):
        return []

    marker = canary or new_canary()
    plan = probe.plan(target, marker)
    if not plan.attempts:
        return []

    trials = TrialBudget(probe.meta.default_trials).resolve(target.trials)
    records: list[TrialRecord] = []

    control_successes, control_trials = await _run_set(
        probe, plan.controls, ctx, ask, trials, records
    )
    per_attempt = await _run_each(probe, plan.attempts, ctx, ask, trials, records)

    # The measurement is of the *strongest* technique, not the average of
    # them. A probe offers several framings of one idea, and pooling them
    # means a framing that works every time and two that never do average
    # into "inconclusive" — reporting a reliably exploitable target as
    # clean. Which framing won is recorded, so the finding names the
    # technique that actually worked.
    best_id, attack_successes, attack_trials = _strongest(per_attempt)

    measurement: Measurement = measure(
        attack_successes=attack_successes,
        attack_trials=attack_trials,
        control_successes=control_successes,
        control_trials=control_trials,
        rule=DEFAULT_RULE,
    )
    outcome = ProbeOutcome(
        measurement=measurement,
        records=tuple(records),
        canary=marker,
        best_attempt_id=best_id,
    )
    return probe.report(target, outcome)


def _strongest(per_attempt: dict[str, tuple[int, int]]) -> tuple[str | None, int, int]:
    """The attempt with the most successes; ties go to the one that spent
    fewer trials, so a cheaper technique wins an otherwise equal contest."""
    if not per_attempt:
        return (None, 0, 0)
    best_id = max(
        per_attempt,
        key=lambda attempt_id: (per_attempt[attempt_id][0], -per_attempt[attempt_id][1]),
    )
    successes, trials = per_attempt[best_id]
    return (best_id, successes, trials)


async def _run_each(
    probe: AiProbe,
    attempts: tuple[Attempt, ...],
    ctx: RunContext,
    ask: Ask,
    trials: int,
    records: list[TrialRecord],
) -> dict[str, tuple[int, int]]:
    """Trials for each attempt separately, so each technique gets its own rate."""
    per_attempt: dict[str, tuple[int, int]] = {}
    for attempt in attempts:
        successes, performed = await _run_set(probe, (attempt,), ctx, ask, trials, records)
        if performed:
            per_attempt[attempt.id] = (successes, performed)
    return per_attempt


async def _run_set(
    probe: AiProbe,
    attempts: tuple[Attempt, ...],
    ctx: RunContext,
    ask: Ask,
    trials: int,
    records: list[TrialRecord],
) -> tuple[int, int]:
    successes = 0
    performed = 0

    for attempt in attempts:
        for _ in range(trials):
            # A halted run stops mid-probe rather than finishing the set:
            # the partial counts are still reported honestly, and a smaller
            # trial count simply widens the interval.
            if ctx.halted or ctx.kill_switch.tripped:
                return successes, performed

            try:
                response = await ask(attempt.prompt)
            except Exception:  # noqa: BLE001 - an unanswered trial is not a success
                continue

            detection = probe.detect(attempt, response)
            performed += 1
            if detection.succeeded:
                successes += 1

            # Redact here, once, rather than trusting every probe to
            # remember. A target can disclose a credential in response to
            # any prompt, not only to the probe that went looking for one.
            safe_text = redact(response.text or "").redacted_text

            records.append(
                TrialRecord(
                    attempt_id=attempt.id,
                    prompt=attempt.prompt,
                    is_control=attempt.is_control,
                    succeeded=detection.succeeded,
                    reason=detection.reason,
                    response_text=safe_text[:MAX_RESPONSE_CHARS],
                    detection_evidence=detection.evidence,
                )
            )

    return successes, performed
