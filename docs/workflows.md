# Workflows

A workflow is five stages: something happens, a plan is derived from it,
actions run, evidence is sealed, a result is decided.

That is not a new capability. It is the shape this platform already had, made
explicit and stored, so two questions become answerable from a record instead of
from logs:

* **Why did this run do what it did?** The plan is derived from the trigger and
  the target's configuration and nothing else, and every action it *skipped* is
  stored with its reason.
* **Did anything change between these two commits?** Two plans have the same
  digest exactly when they would do the same things.

## The stages

| Stage | What it does | What it may depend on |
|---|---|---|
| `trigger` | Records what happened | A repository change, a pull request, a schedule, or a person |
| `plan` | Derives the action list | The trigger and the target's configuration — nothing else |
| `actions` | Runs what the plan named | The same scan path the API uses, under the same scope engine |
| `evidence` | Seals what was observed | Redaction happens before the write, as everywhere else |
| `result` | Decides pass or fail | `gate.evaluate` over findings' **real fields** |

There is deliberately no branching, no user-defined step and no expression
language. A plan is a list of actions the platform already knows how to run,
and that limitation is what keeps the result deterministic.

## A workflow gains no authority

Triggering a workflow requires **security engineer** — the same role
`POST /runs` requires. A workflow that could start a scan with less authority
than starting a scan would be a way around the role, not a feature.

Defining or changing one requires **admin**, because the gate is what decides
whether a release ships. A change to `gate_config` is recorded in the audit log
as a change to the gate, not as an unlabelled "updated".

The actions themselves run through the same authorization check and the same
scope engine as any other assessment. If that check refuses, the workflow is
recorded as `refused` with the reason — not `failed`, because "we were not
authorized to do this" and "we tried and it broke" are different facts.

## An AI recommendation cannot change a gate decision

This is the phase's acceptance criterion, and it is enforced structurally
rather than by policy:

* `decide()` in `app/core/workflow/result.py` takes findings and a gate
  configuration. **It has no parameter for drafts, recommendations or
  suggestions**, so there is no argument a caller could pass to influence it.
* It builds its `GateFinding`s from each finding's real columns. AI drafts live
  in a separate table (`ai_drafts`) that this module never imports — asserted by
  a test that parses the module's imports rather than grepping its text.
* `tests/test_workflow.py` stores a draft proposing a different severity and a
  different status, re-runs the gate, and asserts the decision is byte-identical.

Adding a `drafts` parameter to `decide()` makes
`test_the_decision_function_takes_no_recommendation_parameter` fail. That is
how the property is kept, not by remembering it.

## A misconfigured gate never passes

A gate configuration is validated at two points:

1. **On write.** `POST`/`PATCH .../workflows` parses it through the same
   `load_config` the CLI gate uses and returns 422 if it does not parse. A typo
   like `max_hihg: 0` is rejected where someone typed it.
2. **On evaluation.** If a stored configuration somehow cannot be parsed, the
   workflow run is recorded as `refused`. It is never silently replaced with the
   default, and it never reports a pass.

## The API

```
POST   /api/v1/organizations/{org}/workflows                    admin
GET    /api/v1/organizations/{org}/workflows                    analyst
GET    /api/v1/organizations/{org}/workflows/{id}               analyst
PATCH  /api/v1/organizations/{org}/workflows/{id}               admin
DELETE /api/v1/organizations/{org}/workflows/{id}               admin
POST   /api/v1/organizations/{org}/workflows/{id}/runs          security engineer
GET    /api/v1/organizations/{org}/workflows/{id}/runs          analyst
```

Creating one:

```bash
curl -X POST "$AEGIS/organizations/$ORG/workflows" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
        "name": "main branch",
        "target_id": "'"$TARGET"'",
        "trigger_kind": "repository_change",
        "gate_config": {"fail_on": ["critical", "high"], "max_medium": 5}
      }'
```

Triggering one. A caller may describe the trigger and nothing else — not the
plan, not the actions, not the gate:

```bash
curl -X POST "$AEGIS/organizations/$ORG/workflows/$WF/runs" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"ref": "refs/heads/main", "commit": "'"$GITHUB_SHA"'"}'
```

The response carries the plan, the digest, the five stage records, and the gate
decision with the same exit codes `docs/cicd.md` documents:

| Exit code | Meaning |
|---|---|
| 0 | Gate passed |
| 1 | Gate failed |
| 2 | Configuration error |
| 3 | Authorization error |
| 4 | Scope violation |

## What is not built

Stated rather than implied:

* **No inbound webhook endpoint.** `trigger_kind` includes
  `repository_change` and `pull_request`, but nothing here accepts an event
  *from* a code host. That needs an authenticated endpoint with replay
  protection, and half of it would be worse than none. Drive workflows from CI,
  which already authenticates with an API key.
* **No scheduler.** `SCHEDULE` is a valid trigger kind and nothing fires it;
  use cron and the API.
* **Scan actions are planned here and executed by the assessment path.**
  Triggering a workflow through the API records the trigger, the plan and the
  gate decision over findings that already exist. It does not queue an
  assessment run on its own — one code path for "run an assessment", not two.
  `docs/roadmap.md` records this as the phase's deliberate boundary.
