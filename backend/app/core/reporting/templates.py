"""Audience templates (docs/BUILD_SPEC.md §14, Master Prompt §25).

A template chooses **sections**, never facts. §14 is explicit: "same
underlying data, different renderings, never different facts". So a template
is a list of section keys and nothing more — there is no hook here for a
template to recompute a count, soften a severity, or drop a finding. An
executive report omits probe ids; it does not omit findings.
"""

from enum import StrEnum


class Section(StrEnum):
    EXECUTIVE_SUMMARY = "executive_summary"
    AUTHORIZATION_AND_SCOPE = "authorization_and_scope"
    METHODOLOGY = "methodology"
    ATTACK_SURFACE = "attack_surface"
    RISK_SUMMARY = "risk_summary"
    FINDINGS_BY_SEVERITY = "findings_by_severity"
    AI_FINDINGS = "ai_findings"
    API_FINDINGS = "api_findings"
    APPSEC_FINDINGS = "appsec_findings"
    FRAMEWORK_COVERAGE = "framework_coverage"
    REMEDIATION_PLAN = "remediation_plan"
    RETEST_RESULTS = "retest_results"
    APPENDIX = "appendix"


class Template(StrEnum):
    TECHNICAL = "technical"
    EXECUTIVE = "executive"
    DEVELOPER = "developer"
    COMPLIANCE = "compliance"


# Authorization and scope appears in every template. It carries the record of
# who permitted this and what was excluded, which is the part a reader needs
# most when the report turns up in a dispute.
_SECTIONS: dict[Template, tuple[Section, ...]] = {
    Template.TECHNICAL: (
        Section.EXECUTIVE_SUMMARY,
        Section.AUTHORIZATION_AND_SCOPE,
        Section.METHODOLOGY,
        Section.ATTACK_SURFACE,
        Section.RISK_SUMMARY,
        Section.FINDINGS_BY_SEVERITY,
        Section.AI_FINDINGS,
        Section.API_FINDINGS,
        Section.APPSEC_FINDINGS,
        Section.FRAMEWORK_COVERAGE,
        Section.REMEDIATION_PLAN,
        Section.RETEST_RESULTS,
        Section.APPENDIX,
    ),
    Template.EXECUTIVE: (
        Section.EXECUTIVE_SUMMARY,
        Section.AUTHORIZATION_AND_SCOPE,
        Section.RISK_SUMMARY,
        Section.FRAMEWORK_COVERAGE,
        Section.REMEDIATION_PLAN,
    ),
    # Framework coverage is here for its second half rather than its first:
    # a developer has little use for a list of framework categories, but
    # "what did this run not look at" is exactly what they need before
    # concluding a file is clean. Every template carries that list.
    Template.DEVELOPER: (
        Section.AUTHORIZATION_AND_SCOPE,
        Section.FINDINGS_BY_SEVERITY,
        Section.REMEDIATION_PLAN,
        Section.FRAMEWORK_COVERAGE,
        Section.APPENDIX,
    ),
    Template.COMPLIANCE: (
        Section.EXECUTIVE_SUMMARY,
        Section.AUTHORIZATION_AND_SCOPE,
        Section.METHODOLOGY,
        Section.FRAMEWORK_COVERAGE,
        Section.APPENDIX,
    ),
}

# §14: the executive template carries no probe ids. The rule is about the
# *audience*, not about hiding anything — a probe id means nothing to a
# non-specialist reader and invites them to treat it as a reference number.
_HIDE_PROBE_IDS = frozenset({Template.EXECUTIVE})


def sections_for(template: Template) -> tuple[Section, ...]:
    return _SECTIONS[template]


def shows_probe_ids(template: Template) -> bool:
    return template not in _HIDE_PROBE_IDS
