# The dashboard

A server-rendered dashboard at `/app`, served by the same FastAPI application as
the API. Jinja2 templates, one inline stylesheet, no build step and no
`node_modules`.

```
/app                                        organizations you belong to
/app/organizations/{org}                    overview
/app/organizations/{org}/findings           open findings, filterable by severity
/app/organizations/{org}/runs               assessment runs
/app/organizations/{org}/workflows          workflows and their runs
/app/organizations/{org}/targets            configuration, and what blocks a scan
```

It authenticates with the session cookie the API's `/auth/login` and
`/auth/register` set. There is no sign-in form: a second credential path is a
second thing to get wrong.

## It is read-only, and that is a security decision

Every route under `/app` is a `GET`. Not "mostly", and not "for now" —
`tests/test_web.py::test_every_dashboard_route_is_a_get` walks the route table
and fails if a non-GET route is ever added.

The reason is in `docs/security-review.md`: this platform has **no CSRF token**.
A page that authenticates by cookie and changes state would be forgeable from
any other page the operator had open. Rather than ship that and hope
`SameSite=Lax` holds, the dashboard shows the action, disables it, and says
both why it is disabled and which API call performs it:

> **Start a run** *(disabled)*
> The dashboard is read-only: it authenticates by session cookie and this
> platform has no CSRF token, so a state-changing page route would be forgeable.
> Use the API or the CLI. `POST /api/v1/organizations/{organization_id}/runs`

That is §27's *"every visible action works or is disabled with a reason"* met
honestly. A greyed-out button with no explanation is a dead end; so is hiding
the button and leaving the operator to wonder.

If CSRF protection is added later, these routes become the obvious place to put
the actions back — and the test above is what will make that a deliberate change.

## Every number is a query

§27's other rule: *no hardcoded dashboard values*. Every figure the dashboard
renders comes from `app/web/queries.py`, and nothing else is passed to a
template. A template that wanted a number not in that module would have to add
it there first.

`tests/test_web.py::test_every_number_on_the_overview_comes_from_a_query` reads
the card values and the severity table **back out of the rendered HTML** and
requires the whole set to equal what the query returns, before and after rows
change. The first version of that test checked the query object instead and
passed when a card was replaced with a literal `0`; it was rewritten after that
failure, and now fails on exactly that edit.

Two rules the queries follow:

* **Zero and unknown are different.** A count of zero findings is a fact and
  renders as `0`. A value that was never decided is not, and renders as what it
  is: a workflow run whose gate did not run shows *not decided*, never *pass*;
  a finding with no evidence bundle shows *none*, never an empty cell. Today
  every count on the overview is computable, so none of them is nullable — if
  one ever isn't, it says so rather than rendering a confident `0`.
* **Everything is organization-scoped at the database level**, so a missing
  filter is a missing row rather than a leaked one. Each route depends on
  `require_membership(...)`, and a non-member gets the same **404** the API
  gives — 403 would confirm the organization exists.

## The targets page names what blocks a scan

A target with no authorization grant is refused at run time. A dashboard that
listed only its name would leave an operator to discover that by trying, so the
page states the blockers: no valid authorization grant, no rules of engagement,
no adapter configured. An expired grant renders as `expired`, never as
`granted` — the window is checked per request, and the dashboard must not say
the opposite of what the orchestrator is about to do.

## HTMX

The templates carry `hx-get` / `hx-target` attributes and the handlers honour
the `HX-Request` header, returning the fragment instead of the page. One
handler, one query, two renderings — a partial with its own handler would be a
second source of truth for the same numbers.

**HTMX itself is not committed**, and the base template renders no `<script>`
tag unless you vendor it:

```bash
curl -fsSL -o backend/app/web/static/htmx.min.js \
  https://cdn.jsdelivr.net/npm/htmx.org@2.0.4/dist/htmx.min.js
```

There is deliberately no CDN tag. Fetching unpinned third-party script onto the
page where findings are read is a supply-chain decision, and whoever makes it
should be the person who checked the hash.
`tests/test_web.py::test_no_template_carries_a_cdn_script_tag` enforces that
every script a template loads is served by this application.

**Nothing breaks without it.** Every page is a complete server-rendered
document reachable by an ordinary link; HTMX only swaps a fragment instead of
the page.

## Templates escape what they render

A findings dashboard renders attacker-influenced text: a probe's payload,
echoed back by the target and stored on the finding. Autoescaping is on and
asserted, because rendering that raw would make this platform's own dashboard
the stored-XSS sink it tests its clients for.

## What replaced what

The Next.js scaffold from Phase 1 remains in `frontend/` and is not the
dashboard. `docs/roadmap.md` records that.
