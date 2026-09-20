"""Name-confusion signals: is this package the one you meant?

The honest framing matters more here than anywhere else in this codebase,
because the obvious version of this check is worse than nothing.

A name-similarity score is **not** evidence of malice. `python-dateutil` and
`dateutil` differ by an edit distance that would flag either as squatting the
other; both are real. So this engine never reports "malicious package". It
reports a *signal* — a name one edit away from a widely-used package, a
scoped-package name that also exists publicly, an install hook in a manifest —
at low severity, with the reasoning shown, for a human to look at.

Two things it deliberately does not do:

* **It does not query a registry.** Asking "does a package with this name exist
  upstream?" would send the client's dependency list to a third party, which is
  the opt-in disclosure decision `pip-audit` already models. Without that
  lookup, dependency-confusion detection is limited to what the manifests
  themselves reveal, and the finding says so.
* **It does not invent an advisory identifier.** There is no CVE for "this name
  looks odd", and §28 forbids manufacturing one. These findings carry only the
  platform's own rule IDs.

The popular-name list below is short and hand-maintained on purpose: a long
generated list would produce many low-value near-matches, and the value of this
check is entirely in its precision.
"""

from __future__ import annotations

from app.core.appsec.supplychain.manifests import Dependency

#: Widely-installed packages whose names get impersonated. Short by design.
POPULAR: dict[str, frozenset[str]] = {
    "pypi": frozenset(
        {
            "requests",
            "urllib3",
            "numpy",
            "pandas",
            "flask",
            "django",
            "cryptography",
            "boto3",
            "setuptools",
            "pyyaml",
            "jinja2",
            "sqlalchemy",
            "pytest",
            "click",
            "certifi",
            "colorama",
            "python-dateutil",
            "beautifulsoup4",
            "pillow",
            "scipy",
        }
    ),
    "npm": frozenset(
        {
            "react",
            "lodash",
            "express",
            "axios",
            "chalk",
            "commander",
            "debug",
            "webpack",
            "typescript",
            "eslint",
            "moment",
            "uuid",
            "dotenv",
            "next",
            "vue",
            "jest",
            "rimraf",
            "async",
        }
    ),
}

#: Characters that are visually confusable in a package name. `rn` for `m` is
#: the classic; `1`/`l` and `0`/`o` are the others that survive a quick read.
_HOMOGLYPHS = (("rn", "m"), ("vv", "w"), ("1", "l"), ("0", "o"), ("5", "s"))

#: npm lifecycle scripts that run code during `npm install`. Their presence is
#: not a vulnerability — plenty of legitimate packages build native code this
#: way — but it is where an install-time supply-chain attack lands.
INSTALL_HOOKS = ("preinstall", "install", "postinstall", "preuninstall", "postuninstall")


def edit_distance(left: str, right: str, *, cap: int = 3) -> int:
    """Levenshtein distance, stopping once it exceeds `cap`.

    Capped because the answer is only interesting when it is small, and the
    early exit keeps this linear-ish over a whole dependency list.
    """
    if abs(len(left) - len(right)) > cap:
        return cap + 1
    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, start=1):
        current = [i]
        for j, right_char in enumerate(right, start=1):
            current.append(
                min(
                    previous[j] + 1,
                    current[j - 1] + 1,
                    previous[j - 1] + (left_char != right_char),
                )
            )
        if min(current) > cap:
            return cap + 1
        previous = current
    return previous[-1]


def _normalized(name: str) -> str:
    """PEP 503-ish normalization, applied to npm names too.

    Both ecosystems treat `-` and `_` as distinct, which is precisely what makes
    `python-dateutil` vs `python_dateutil` a usable impersonation, so comparing
    the normalized forms is the point.
    """
    return name.strip().lower().replace("_", "-").replace(".", "-").lstrip("@")


def _homoglyph_variants(name: str) -> set[str]:
    variants = {name}
    for wrong, right in _HOMOGLYPHS:
        for source, target in ((wrong, right), (right, wrong)):
            if source in name:
                variants.add(name.replace(source, target))
    return variants


def _transpositions(name: str) -> set[str]:
    """Every adjacent-character swap of `name`.

    Its own check rather than a wider edit-distance cap, because Levenshtein
    scores a transposition as two edits — so `reqeusts` for `requests` would
    otherwise need `cap=2`, which also admits genuinely different names.
    A swap is the commonest typo and the commonest squat, and this catches it
    without loosening anything else.
    """
    return {
        name[:index] + name[index + 1] + name[index] + name[index + 2 :]
        for index in range(len(name) - 1)
        if name[index] != name[index + 1]
    }


def near_matches(dependency: Dependency) -> list[tuple[str, str]]:
    """`(popular_name, why)` for each popular package this name resembles.

    An exact match returns nothing: depending on `requests` is depending on
    `requests`.
    """
    popular = POPULAR.get(dependency.ecosystem)
    if not popular:
        return []

    candidate = _normalized(dependency.name)
    if candidate in {_normalized(name) for name in popular}:
        return []

    matches: list[tuple[str, str]] = []
    for name in sorted(popular):
        target = _normalized(name)

        if candidate in _homoglyph_variants(target) or target in _homoglyph_variants(candidate):
            matches.append((name, "differs only by visually confusable characters"))
            continue

        if candidate in _transpositions(target):
            matches.append((name, f"two adjacent characters swapped from {name!r}"))
            continue

        # A prefix or suffix bolted onto a real name: `python-requests`,
        # `requests-oauth2`. Common in legitimate packages too, hence the
        # wording of the finding.
        if candidate != target and (
            candidate.startswith(f"{target}-") or candidate.endswith(f"-{target}")
        ):
            matches.append((name, f"wraps the name of the widely-used {name!r}"))
            continue

        # Only worth comparing by edit distance when the name is long enough
        # for one edit to be surprising. Short names differ by one edit all the
        # time and mean nothing.
        if len(target) >= 5:
            distance = edit_distance(candidate, target, cap=1)
            if distance == 1:
                matches.append((name, f"one character from {name!r}"))

    return matches


def unpinned(dependency: Dependency) -> bool:
    """No version constraint at all.

    Relevant here because an unpinned dependency takes whatever the registry
    serves next, which is how a compromised release reaches a build with no
    change on the consuming side.
    """
    spec = dependency.version_spec.strip()
    return not spec or spec in {"*", "latest", "x"}
