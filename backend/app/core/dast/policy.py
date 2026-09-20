"""Which third-party checks may run, derived from the rules of engagement.

A DAST scanner's template set is the difference between a report and an
incident. Nuclei ships templates that write files, trigger out-of-band
callbacks, and exploit remote code execution; ZAP's active scan submits forms
and mutates state. None of that may run because someone typed a command — it
runs because an authorization said state may change.

So the allowlist is **derived**, never passed:

* Under the default (`allow_state_mutation=False`) only passive and
  read-only detection runs. Anything tagged as intrusive, destructive, or
  requiring an out-of-band callback is excluded.
* With `allow_state_mutation=True` the intrusive set is permitted, and the
  finding says so — a reader must be able to tell a passive result from one
  produced by an active scan.
* **Out-of-band callbacks stay excluded either way.** An `interactsh` template
  makes the target contact a third-party server the engagement never
  authorized, which is an egress path the scope engine cannot see. Enabling it
  needs a collaborator the operator controls, and that is not built
  (`docs/dast.md`).
"""

from __future__ import annotations

from dataclasses import dataclass

#: Nuclei tags that never run here, whatever the rules of engagement say.
#: `oast`, `interactsh` and `blind` all mean "the target contacts a server we do
#: not control", which is an unauthorized egress path rather than a test.
NEVER_TAGS: tuple[str, ...] = (
    "oast",
    "interactsh",
    "blind",
    "dos",
    "fuzzing-req",
)

#: Tags permitted only when `allow_state_mutation` is set. These write, delete,
#: upload, or execute.
MUTATING_TAGS: tuple[str, ...] = (
    "intrusive",
    "rce",
    "sqli",
    "file-upload",
    "deserialization",
    "injection",
    "traversal",
)

#: The read-only set. Detection and disclosure only: what is exposed, what
#: version it is, how it is configured.
PASSIVE_TAGS: tuple[str, ...] = (
    "exposure",
    "misconfig",
    "tech",
    "detect",
    "disclosure",
    "default-login",
    "ssl",
    "headers",
    "cve",
)

#: Nuclei severities worth reporting. `info` is excluded because a nuclei
#: `info` template fires on almost every site and would bury the rest.
SEVERITIES: tuple[str, ...] = ("low", "medium", "high", "critical")


@dataclass(frozen=True)
class ToolPolicy:
    """What a DAST tool may do on this run."""

    allow_state_mutation: bool
    include_tags: tuple[str, ...]
    exclude_tags: tuple[str, ...]
    severities: tuple[str, ...]
    #: Methods the rules of engagement permit. A scanner asked to test a target
    #: whose RoE allows only GET must not be handed a POST-based template set.
    allowed_methods: tuple[str, ...]

    @property
    def mode(self) -> str:
        """`passive` or `active`, for the finding to state plainly."""
        return "active" if self.allow_state_mutation else "passive"


def tool_policy(*, allow_state_mutation: bool, allowed_methods: tuple[str, ...]) -> ToolPolicy:
    """Derive the policy. There is no parameter for widening it further.

    `NEVER_TAGS` is in `exclude_tags` in both branches, so an out-of-band
    template cannot run even with state mutation allowed — that is a separate
    decision from "may this change state", and one this platform has not built
    the infrastructure to make safely.
    """
    if allow_state_mutation:
        include = (*PASSIVE_TAGS, *MUTATING_TAGS)
        exclude = NEVER_TAGS
    else:
        include = PASSIVE_TAGS
        # Mutating tags are excluded as well as not included: a template can
        # carry several tags, and an `exposure,intrusive` template must not slip
        # in on the strength of the first one.
        exclude = (*NEVER_TAGS, *MUTATING_TAGS)

    return ToolPolicy(
        allow_state_mutation=allow_state_mutation,
        include_tags=include,
        exclude_tags=exclude,
        severities=SEVERITIES,
        allowed_methods=tuple(method.upper() for method in allowed_methods),
    )


def zap_scan_mode(policy: ToolPolicy) -> str:
    """`baseline` (spider + passive rules) or `full` (active attack rules).

    ZAP's active scan submits forms and sends attack payloads, so it is a
    state-changing operation by definition.
    """
    return "full" if policy.allow_state_mutation else "baseline"
