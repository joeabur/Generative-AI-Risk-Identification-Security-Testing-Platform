"""Enforce the per-package coverage floors (docs/BUILD_SPEC.md §24).

§24 sets three numbers, not one: **≥80% overall, ≥85% on `core/`, ≥95% on
`core/scope/`**. Only the first is something `--cov-fail-under` can express,
and on its own it is the weakest of the three — a large, well-tested API
surface keeps the headline healthy while the scope engine, which is the entire
safety boundary, quietly rots. So the floors that matter are checked here.

The thresholds are the spec's, not a record of wherever the suite happens to
sit. §2.8 forbids unmeasured coverage claims, and a floor set to today's number
is the same failure wearing a number: it can only ever be met.

No network, no side effects: it reads the JSON `pytest-cov` already wrote.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from dataclasses import dataclass

#: (path prefix, floor). Ordered most specific first, because a file under
#: `app/core/scope/` belongs to the scope floor, not the general core one.
FLOORS: tuple[tuple[str, float], ...] = (
    ("app/core/scope/", 95.0),
    ("app/core/", 85.0),
)

#: What `--cov-fail-under` enforces, repeated here so one command prints the
#: whole picture rather than two halves in two places.
OVERALL_FLOOR = 80.0


@dataclass(frozen=True)
class Measured:
    label: str
    covered: int
    statements: int
    floor: float

    @property
    def percent(self) -> float:
        # No statements means nothing to cover. Reporting 0% would fail a build
        # over an empty package; reporting 100% would claim coverage of
        # nothing. Neither is a measurement, so it is treated as passing and
        # the count is printed so a reader sees why.
        return 100.0 if self.statements == 0 else 100.0 * self.covered / self.statements

    @property
    def ok(self) -> bool:
        return self.percent >= self.floor


def measure(report: dict[str, object]) -> list[Measured]:
    files = report.get("files")
    if not isinstance(files, dict):
        raise ValueError("coverage report has no 'files' section")

    buckets: dict[str, list[int]] = {prefix: [0, 0] for prefix, _ in FLOORS}
    overall = [0, 0]

    for path, data in files.items():
        summary = data.get("summary", {}) if isinstance(data, dict) else {}
        covered = int(summary.get("covered_lines", 0))
        statements = int(summary.get("num_statements", 0))
        overall[0] += covered
        overall[1] += statements
        for prefix, _ in FLOORS:
            if path.startswith(prefix):
                buckets[prefix][0] += covered
                buckets[prefix][1] += statements
                # Most specific wins: a scope file is not also counted as a
                # general core file, or the scope floor would be diluted by the
                # package it is meant to be stricter than.
                break

    measured = [
        Measured(
            label=prefix, covered=buckets[prefix][0], statements=buckets[prefix][1], floor=floor
        )
        for prefix, floor in FLOORS
    ]
    measured.append(
        Measured(label="overall", covered=overall[0], statements=overall[1], floor=OVERALL_FLOOR)
    )
    return measured


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("report", help="coverage JSON written by pytest-cov")
    args = parser.parse_args(argv)

    path = pathlib.Path(args.report)
    if not path.is_file():
        print(f"coverage report not found: {path}", file=sys.stderr)
        return 2

    results = measure(json.loads(path.read_text()))
    failed = [item for item in results if not item.ok]

    for item in results:
        mark = "ok  " if item.ok else "FAIL"
        print(
            f"{mark} {item.label:<20} {item.percent:6.2f}%  "
            f"(floor {item.floor:.0f}%, {item.covered}/{item.statements} statements)"
        )

    if failed:
        print("", file=sys.stderr)
        for item in failed:
            print(
                f"{item.label} is at {item.percent:.2f}%, below the §24 floor of "
                f"{item.floor:.0f}%.",
                file=sys.stderr,
            )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
