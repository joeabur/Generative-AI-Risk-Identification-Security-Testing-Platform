"""Deriving a plan from a trigger and a target's configuration.

Pure, and deliberately so: no database, no clock, no randomness. The same
trigger against the same configuration produces the same plan, byte for byte,
which is what makes `Plan.digest` a useful thing to store and compare.

Every action is either planned or **skipped with a reason**. A plan that
silently omitted the AI scan because no adapter was configured would leave
someone reading the result unable to tell "nothing was found" from "nothing was
looked for" — which is the same coverage-honesty rule the reports follow.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.workflow.contract import ActionKind, Plan, PlannedAction, Trigger, TriggerKind


@dataclass(frozen=True)
class TargetCapabilities:
    """What this target is configured for.

    A flat, boolean view of the target row, so the planner does not depend on
    the ORM and can be exercised without a database.
    """

    kind: str
    has_code_repo: bool = False
    has_openapi: bool = False
    has_adapter: bool = False
    has_synthetic_accounts: bool = False
    #: A code-host connection exists and this trigger names a pull request.
    can_publish_pr: bool = False
    has_notification_channel: bool = False


def _appsec(trigger: Trigger, target: TargetCapabilities) -> PlannedAction:
    if not target.has_code_repo:
        return PlannedAction(
            ActionKind.APPSEC_SCAN,
            "no repository is configured on this target",
            skipped=True,
        )
    return PlannedAction(ActionKind.APPSEC_SCAN, "a repository is configured")


def _api(trigger: Trigger, target: TargetCapabilities) -> PlannedAction:
    if not target.has_openapi:
        return PlannedAction(
            ActionKind.API_SCAN,
            "no OpenAPI document has been uploaded, so there is no surface to test",
            skipped=True,
        )
    return PlannedAction(ActionKind.API_SCAN, "an OpenAPI document defines the surface")


def _ai(trigger: Trigger, target: TargetCapabilities) -> PlannedAction:
    if not target.has_adapter:
        return PlannedAction(
            ActionKind.AI_SCAN,
            "no conversational adapter is configured",
            skipped=True,
        )
    return PlannedAction(ActionKind.AI_SCAN, "a conversational adapter is configured")


def _dast(trigger: Trigger, target: TargetCapabilities) -> PlannedAction:
    if target.kind != "web_app":
        return PlannedAction(
            ActionKind.DAST_SCAN,
            f"DAST runs only for kind: web_app; this target is {target.kind}",
            skipped=True,
        )
    return PlannedAction(ActionKind.DAST_SCAN, "the target is a web application")


def build_plan(trigger: Trigger, target: TargetCapabilities) -> Plan:
    """The plan for this trigger. Deterministic.

    A repository change plans the code engines first because that is what
    changed; a pull request plans the same set plus publishing. Neither runs
    anything the target is not configured for, and each omission is recorded.
    """
    actions: list[PlannedAction] = []

    if trigger.kind in (TriggerKind.REPOSITORY_CHANGE, TriggerKind.PULL_REQUEST):
        # The code changed, so the code engines lead. The dynamic engines still
        # run where configured: a dependency bump can change runtime behaviour,
        # and a workflow that only re-ran SAST would miss it.
        actions.append(_appsec(trigger, target))
        actions.append(_api(trigger, target))
        actions.append(_ai(trigger, target))
        actions.append(_dast(trigger, target))
    else:
        actions.append(_api(trigger, target))
        actions.append(_ai(trigger, target))
        actions.append(_dast(trigger, target))
        actions.append(_appsec(trigger, target))

    # Normalization and correlation always run, even when every scan was
    # skipped: they are what turn results into findings, and a run with no new
    # results still has to reconcile against what is already known.
    actions.append(PlannedAction(ActionKind.NORMALIZE, "results become findings"))
    actions.append(PlannedAction(ActionKind.CORRELATE, "findings are deduplicated by fingerprint"))
    # The gate always runs. A workflow whose gate was conditional would be a
    # workflow whose verdict depended on configuration rather than on findings.
    actions.append(PlannedAction(ActionKind.GATE, "the result is decided by the gate"))

    if target.has_notification_channel:
        actions.append(PlannedAction(ActionKind.NOTIFY, "a notification channel is subscribed"))
    else:
        actions.append(
            PlannedAction(ActionKind.NOTIFY, "no notification channel is configured", skipped=True)
        )

    if trigger.kind is TriggerKind.PULL_REQUEST and trigger.pull_number:
        if target.can_publish_pr:
            actions.append(
                PlannedAction(ActionKind.PUBLISH_PR, "a code host connection is configured")
            )
        else:
            actions.append(
                PlannedAction(
                    ActionKind.PUBLISH_PR,
                    "no code host connection is configured for this organization",
                    skipped=True,
                )
            )
    else:
        actions.append(
            PlannedAction(ActionKind.PUBLISH_PR, "this trigger names no pull request", skipped=True)
        )

    return Plan(actions=tuple(actions))
