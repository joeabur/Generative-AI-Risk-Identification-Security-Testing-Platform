"""End-of-life data for common runtimes, vendored with a snapshot date.

Vendored rather than fetched, for the same reason `pip-audit`'s advisory lookup
is opt-in: sending a client's runtime inventory to a third party is a disclosure
decision an operator makes, not one a scanner makes quietly. The cost is that
this table goes stale, so:

* `AS_OF` is the date it was compiled, and **every finding states it**. A reader
  can then tell "supported as of six months ago" from "supported today".
* A runtime or version **not in the table is reported as not assessed**, never
  as supported. Absence of data is not evidence of support, and this is the one
  mistake that would make the engine actively misleading.
* Dates are the vendor's published EOL, to the day where one is published and to
  the month otherwise (normalised to the first of that month, which errs
  towards calling something EOL slightly early rather than slightly late).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

#: When this table was compiled. Stated in every finding it produces.
AS_OF = date(2026, 9, 1)


@dataclass(frozen=True)
class ReleaseSupport:
    runtime: str
    #: The major or major.minor series, as a project pins it: "3.9", "18", "1.21".
    series: str
    end_of_life: date
    #: Where the date came from, so a reader can check it.
    source: str


_SOURCES = {
    "python": "https://devguide.python.org/versions/",
    "node": "https://github.com/nodejs/release#release-schedule",
    "go": "https://go.dev/doc/devel/release#policy",
    "java": "https://www.oracle.com/java/technologies/java-se-support-roadmap.html",
    "debian": "https://wiki.debian.org/LTS",
    "ubuntu": "https://wiki.ubuntu.com/Releases",
    "alpine": "https://alpinelinux.org/releases/",
    "php": "https://www.php.net/supported-versions.php",
    "ruby": "https://www.ruby-lang.org/en/downloads/branches/",
}


def _entry(runtime: str, series: str, year: int, month: int, day: int = 1) -> ReleaseSupport:
    return ReleaseSupport(runtime, series, date(year, month, day), _SOURCES[runtime])


#: Series this table knows about. A series outside it is "not assessed".
TABLE: tuple[ReleaseSupport, ...] = (
    _entry("python", "3.7", 2023, 6, 27),
    _entry("python", "3.8", 2024, 10, 7),
    _entry("python", "3.9", 2025, 10, 31),
    _entry("python", "3.10", 2026, 10, 31),
    _entry("python", "3.11", 2027, 10, 31),
    _entry("python", "3.12", 2028, 10, 31),
    _entry("python", "3.13", 2029, 10, 31),
    _entry("node", "14", 2023, 4, 30),
    _entry("node", "16", 2023, 9, 11),
    _entry("node", "18", 2025, 4, 30),
    _entry("node", "20", 2026, 4, 30),
    _entry("node", "22", 2027, 4, 30),
    _entry("go", "1.19", 2023, 9, 6),
    _entry("go", "1.20", 2024, 2, 6),
    _entry("go", "1.21", 2024, 8, 13),
    _entry("go", "1.22", 2025, 2, 11),
    _entry("java", "8", 2030, 12, 31),
    _entry("java", "11", 2032, 1, 31),
    _entry("java", "17", 2029, 9, 30),
    _entry("java", "21", 2031, 9, 30),
    _entry("debian", "10", 2024, 6, 30),
    _entry("debian", "11", 2026, 8, 31),
    _entry("debian", "12", 2028, 6, 30),
    _entry("ubuntu", "18.04", 2023, 5, 31),
    _entry("ubuntu", "20.04", 2025, 5, 31),
    _entry("ubuntu", "22.04", 2027, 4, 30),
    _entry("ubuntu", "24.04", 2029, 5, 31),
    _entry("alpine", "3.16", 2024, 5, 23),
    _entry("alpine", "3.17", 2024, 11, 22),
    _entry("alpine", "3.18", 2025, 5, 9),
    _entry("alpine", "3.19", 2025, 11, 1),
    _entry("php", "8.0", 2023, 11, 26),
    _entry("php", "8.1", 2025, 12, 31),
    _entry("php", "8.2", 2026, 12, 31),
    _entry("ruby", "3.0", 2024, 4, 23),
    _entry("ruby", "3.1", 2025, 3, 31),
    _entry("ruby", "3.2", 2026, 3, 31),
)


def _series_candidates(version: str) -> list[str]:
    """The series keys a version could match, most specific first.

    `3.9.18` should match the `3.9` row, and `18.20.4` the `18` row, so both
    the two-part and one-part prefixes are tried — in that order, because
    matching `3` before `3.9` would silently compare against the wrong series.
    """
    parts = version.split(".")
    candidates = []
    if len(parts) >= 2:
        candidates.append(f"{parts[0]}.{parts[1]}")
    candidates.append(parts[0])
    return candidates


def lookup(runtime: str, version: str) -> ReleaseSupport | None:
    """The support row for this version, or None when the table has no answer."""
    normalized = runtime.strip().lower()
    for series in _series_candidates(version.strip()):
        for entry in TABLE:
            if entry.runtime == normalized and entry.series == series:
                return entry
    return None


def is_end_of_life(entry: ReleaseSupport, *, today: date | None = None) -> bool:
    return (today or AS_OF) >= entry.end_of_life
