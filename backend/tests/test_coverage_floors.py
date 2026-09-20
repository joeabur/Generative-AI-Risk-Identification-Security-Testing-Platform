"""The per-package coverage gate (docs/BUILD_SPEC.md §24, §27).

§24 sets three floors — ≥80% overall, ≥85% on `core/`, ≥95% on `core/scope/` —
and only the first is expressible as `--cov-fail-under`. On its own that one is
the weakest: a large, well-tested API surface keeps the headline healthy while
the scope engine, which is the entire safety boundary, rots underneath it.

So the tests below are mostly about the gate being able to *fail*. A gate that
cannot fail is a number in a log.
"""

from __future__ import annotations

import json
import pathlib

import yaml

from scripts.coverage_floors import FLOORS, OVERALL_FLOOR, main, measure

WORKFLOWS = pathlib.Path(__file__).resolve().parents[2] / ".github" / "workflows"


def _report(files: dict[str, tuple[int, int]]) -> dict[str, object]:
    return {
        "files": {
            path: {"summary": {"covered_lines": covered, "num_statements": total}}
            for path, (covered, total) in files.items()
        }
    }


def test_the_floors_are_the_specs_numbers() -> None:
    """Pinned, so nobody can quietly lower a floor to make a build pass.

    §2.8 forbids unmeasured coverage claims, and a floor set to wherever the
    suite happens to sit is the same failure wearing a number: it can only ever
    be met.
    """
    assert dict(FLOORS) == {"app/core/scope/": 95.0, "app/core/": 85.0}
    assert OVERALL_FLOOR == 80.0


def test_a_package_below_its_floor_fails() -> None:
    """The gate's entire job.

    Verified by inverting the comparison in `Measured.ok`: this passes.
    """
    results = measure(
        _report(
            {
                "app/core/scope/engine.py": (50, 100),  # 50%, floor 95
                "app/core/other.py": (100, 100),
            }
        )
    )
    scope = next(item for item in results if item.label == "app/core/scope/")
    assert scope.percent == 50.0
    assert scope.ok is False


def test_the_scope_floor_is_not_diluted_by_the_wider_core_package() -> None:
    """A scope file counts once, against the stricter floor.

    If `app/core/scope/` files were also counted into `app/core/`, a large
    well-covered core would drag the scope percentage up and the 95% floor
    would stop meaning anything — which is the opposite of why it is stricter.

    Verified by removing the `break`: the scope bucket still reads 50% but the
    core bucket silently absorbs its statements.
    """
    results = measure(
        _report(
            {
                "app/core/scope/engine.py": (50, 100),
                "app/core/reporting/build.py": (900, 900),
            }
        )
    )
    core = next(item for item in results if item.label == "app/core/")
    scope = next(item for item in results if item.label == "app/core/scope/")
    assert scope.statements == 100
    # 900 statements, not 1000: the scope file belongs to the stricter bucket.
    assert core.statements == 900
    assert core.percent == 100.0


def test_an_empty_package_neither_fails_nor_claims_coverage() -> None:
    """Zero statements is not zero coverage.

    Failing a build over an empty package is noise; reporting 100% would claim
    coverage of nothing. It passes, and the statement count is printed so a
    reader can see why.
    """
    results = measure(_report({"app/other.py": (10, 10)}))
    scope = next(item for item in results if item.label == "app/core/scope/")
    assert scope.statements == 0
    assert scope.ok is True


def test_the_exit_code_distinguishes_a_failure_from_a_missing_report(
    tmp_path: pathlib.Path,
) -> None:
    """2 means "could not measure", 1 means "measured and too low".

    Collapsing them would let a CI step that never produced a report look
    exactly like one that did and passed.
    """
    assert main([str(tmp_path / "absent.json")]) == 2

    low = tmp_path / "low.json"
    low.write_text(json.dumps(_report({"app/core/scope/engine.py": (1, 100)})))
    assert main([str(low)]) == 1

    high = tmp_path / "high.json"
    high.write_text(json.dumps(_report({"app/core/scope/engine.py": (100, 100)})))
    assert main([str(high)]) == 0


def test_ci_runs_the_gate_and_fails_the_build_on_it() -> None:
    """A gate nothing invokes is a script.

    Verified by deleting the step from `ci.yml`.
    """
    body = (WORKFLOWS / "ci.yml").read_text()
    assert "--cov-fail-under" in body, "ci.yml does not enforce the overall floor"
    assert "scripts.coverage_floors" in body, "ci.yml never checks the per-package floors"

    document = yaml.safe_load(body)
    steps = document["jobs"]["backend"]["steps"]
    names = [str(step.get("name", "")) for step in steps]
    assert any("coverage" in name.lower() for name in names)
