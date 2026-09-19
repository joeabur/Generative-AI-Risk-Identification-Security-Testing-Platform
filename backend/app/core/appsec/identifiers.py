"""Verifying that an identifier came from the tool, not from us
(docs/BUILD_SPEC.md §28; Addendum v2.1 §11).

"Normalization is not a licence to launder an invented identifier through
the pipeline." A CVE number in a report is a claim a reader will act on —
they will look it up, check whether they are affected, and schedule work
around it. A plausible-looking identifier that does not exist wastes that
work and destroys trust in every other identifier in the same report.

So this module is deliberately narrow: it checks *shape*, and every
identifier that reaches a finding must have been present in the tool's own
output. Nothing here constructs an identifier; the only thing it can do is
reject one.
"""

import re

# Shapes defined by their issuers. These match the published formats and
# nothing else, so a near-miss is rejected rather than quietly accepted.
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_GHSA = re.compile(
    r"^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}"
    r"-[23456789cfghjmpqrvwx]{4}$"
)
_CWE = re.compile(r"^CWE-\d{1,5}$")
_OSV = re.compile(r"^[A-Z][A-Z0-9-]{1,20}-\d{4}-\d{1,10}$")
# A tool's own rule id: a dotted or slashed path, as Semgrep, Bandit and
# Checkov all emit. Bounded so an error message cannot become a "rule id".
_RULE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/\-]{1,200}$")


class IdentifierError(ValueError):
    """An identifier is not in a shape its issuer would ever produce."""


def is_cve(value: str) -> bool:
    return bool(_CVE.match(value.strip()))


def is_ghsa(value: str) -> bool:
    return bool(_GHSA.match(value.strip()))


def is_cwe(value: str) -> bool:
    return bool(_CWE.match(value.strip().upper()))


def is_advisory(value: str) -> bool:
    """A CVE, a GHSA, or another OSV-style database identifier (PYSEC, GO…)."""
    value = value.strip()
    return is_cve(value) or is_ghsa(value) or bool(_OSV.match(value))


def is_rule_id(value: str) -> bool:
    return bool(_RULE_ID.match(value.strip()))


def verified_advisories(values: object) -> tuple[str, ...]:
    """Keep only well-formed advisory identifiers, in order, deduplicated.

    Anything else is dropped rather than repaired: an identifier we had to
    fix up is one the tool did not actually report.
    """
    if not isinstance(values, list | tuple):
        return ()
    seen: list[str] = []
    for raw in values:
        value = str(raw).strip()
        if is_advisory(value) and value not in seen:
            seen.append(value)
    return tuple(seen)


def verified_cwes(values: object) -> tuple[str, ...]:
    """Keep only well-formed CWE identifiers the tool itself declared.

    §0 forbids inventing a mapping, so a rule with no CWE produces a finding
    with no CWE — never a guess from the rule's wording.
    """
    if not isinstance(values, list | tuple):
        return ()
    seen: list[str] = []
    for raw in values:
        value = str(raw).strip().upper()
        # Tools write CWEs as "CWE-79", "79", or "cwe-79"; normalising the
        # prefix is formatting, not invention, so it is allowed.
        if value.isdigit():
            value = f"CWE-{value}"
        if is_cwe(value) and value not in seen:
            seen.append(value)
    return tuple(seen)


def require_rule_id(value: str, *, tool: str) -> str:
    if not is_rule_id(value):
        raise IdentifierError(
            f"{tool} produced a finding with no usable rule id ({value!r}); "
            "refusing to report it rather than inventing one"
        )
    return value.strip()
