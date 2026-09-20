# Roles and permissions

## The ladder

```
owner  >  admin  >  security_engineer  >  analyst  >  viewer
```

Each role includes everything below it. Membership is per organization: a user
can be an owner of one and a viewer of another, and the check always resolves
against the organization in the request path.

## What each role can do

| | viewer | analyst | security engineer | admin | owner |
|---|:-:|:-:|:-:|:-:|:-:|
| Read targets, runs, findings, reports, evidence manifests | ✓ | ✓ | ✓ | ✓ | ✓ |
| Scope dry-run / `scope explain` | ✓ | ✓ | ✓ | ✓ | ✓ |
| Download an evidence bundle | | ✓ | ✓ | ✓ | ✓ |
| Change a finding's status, assign remediation | | ✓ | ✓ | ✓ | ✓ |
| List notification channels and pull-request posts | | ✓ | ✓ | ✓ | ✓ |
| Start, cancel or retest a run | | | ✓ | ✓ | ✓ |
| Publish findings to a pull request | | | ✓ | ✓ | ✓ |
| Configure a target's adapter | | | ✓ | ✓ | ✓ |
| Create a target, upload an OpenAPI spec, set RoE | | | | ✓ | ✓ |
| **Grant authorization to test a target** | | | | ✓ | ✓ |
| Manage synthetic accounts | | | | ✓ | ✓ |
| Mint or revoke API keys | | | | ✓ | ✓ |
| Manage notification channels and code-host connections | | | | ✓ | ✓ |
| Add or remove members, change roles | | | | ✓ | ✓ |
| Delete the organization | | | | | ✓ |

## The two placements worth explaining

**Granting authorization is admin, not security engineer.** It is the act the
entire platform is built around — a human taking responsibility for testing a
system. It sits with the people who are accountable for the organization, and
notably *above* the ceiling any API key can reach.

**Publishing to a pull request is security engineer, not admin.** Posting a
check run is part of running an assessment. Requiring an admin would push teams
towards putting an admin credential in CI, which is precisely the outcome the
API-key role cap exists to prevent.

## API key ceilings

| Scope | Acts as |
|---|---|
| `read` | viewer |
| `triage` | analyst |
| `scan` | security engineer |

The cap is applied after the membership check, so a key is always the *lower* of
its scope and the creating user's role.

## Tenant isolation

A request for a resource in an organization the caller does not belong to
returns **404**, never 403. Every query is filtered by `organization_id` at the
database level rather than by checking after loading, so a missing filter is a
missing row, not a leaked one.

`backend/tests/security/test_authorization_matrix.py` drives every route
unauthenticated (expect 401), as a non-member (expect 404), and as an
under-privileged member (expect 403), and holds a pinned route→role table. That
table exists because an earlier version of the test passed while a route was
silently downgraded from analyst to viewer; the pin makes such a change fail
with the route named.
