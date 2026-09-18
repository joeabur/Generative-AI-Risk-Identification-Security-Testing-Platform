"""LLM-as-judge (docs/BUILD_SPEC.md §7.3).

**This ships disabled, and that is the deliberate outcome, not a gap.**

§7.3 states the condition plainly: "An uncalibrated judge does not ship."
Calibration means a labelled fixture set and published precision and recall
numbers. Publishing numbers we have not measured would be worse than having
no judge; running an unmeasured judge and letting its opinion become a
finding would be worse still.

So the judge is present as a disabled seam with the rules encoded in its
type, and `calibrated` has no way to become true without someone doing the
measurement:

* it is off by default and cannot be enabled without calibration evidence;
* its output is a `JudgeOpinion`, never a `ScanResult`, so it cannot become
  a finding on its own (§7.3: "Judge output is a Detection, never a Finding
  directly");
* every deterministic detector in this engine carries its probe alone, so
  nothing depends on the judge existing.

`make calibrate` and the fixture set are the work that turns this on.
"""

from dataclasses import dataclass


class JudgeNotCalibratedError(RuntimeError):
    """Raised on any attempt to use a judge that has not been calibrated."""


@dataclass(frozen=True)
class Calibration:
    """Measured performance against a labelled fixture set.

    There is no default: a `Calibration` exists only because someone ran
    the measurement and wrote the numbers down.
    """

    fixture_set: str
    precision: float
    recall: float
    measured_at: str
    judge_model: str

    def summary(self) -> str:
        return (
            f"{self.judge_model} on {self.fixture_set}: "
            f"precision {self.precision:.2f}, recall {self.recall:.2f} "
            f"(measured {self.measured_at})"
        )


@dataclass(frozen=True)
class JudgeOpinion:
    """A judge's view. Deliberately not a `ScanResult`: an opinion needs a
    deterministic corroborator or a human before it becomes a finding."""

    succeeded: bool
    rationale: str
    judge_model: str
    calibration: Calibration


@dataclass(frozen=True)
class JudgeConfig:
    """Judging configuration. Disabled unless calibration is supplied."""

    enabled: bool = False
    calibration: Calibration | None = None

    def __post_init__(self) -> None:
        if self.enabled and self.calibration is None:
            raise JudgeNotCalibratedError(
                "a judge cannot be enabled without a Calibration: docs/BUILD_SPEC.md "
                "§7.3 requires published precision and recall from a labelled fixture "
                "set before a judge ships"
            )

    def describe(self) -> str:
        """What the report says about judging, either way.

        §14 requires the report to state what was not covered, so a disabled
        judge is reported rather than omitted.
        """
        if not self.enabled or self.calibration is None:
            return (
                "Judge: disabled. No LLM-as-judge was used in this assessment; every "
                "detection here comes from a deterministic detector. Enabling a judge "
                "requires published calibration numbers (docs/BUILD_SPEC.md §7.3)."
            )
        return f"Judge: enabled — {self.calibration.summary()}"


# The default every run uses today.
DISABLED_JUDGE = JudgeConfig()
