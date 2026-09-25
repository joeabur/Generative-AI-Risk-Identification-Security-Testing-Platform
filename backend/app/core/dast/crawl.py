"""A crawler that cannot queue an out-of-scope URL.

The acceptance criterion for this phase (§26 Phase 15) is that a crawl never
fetches an out-of-scope URL *discovered mid-crawl*. The obvious implementation
satisfies that accidentally: queue everything, and let `GatedTransport` refuse
the bad ones when their turn comes. This module deliberately does not do that,
for three reasons.

**A queue of out-of-scope URLs is itself a defect.** It means the crawl's own
state contains a list of places the engagement does not cover. Anything that
later iterates that queue — a retry, a progress display, a debug log, a future
adapter handed "the discovered URLs" — reaches them. The refusal has to happen
before the URL is recorded as work, not before the socket opens.

**"It would have been refused later" is not a control you can test.** A test
that asserts no out-of-scope *request* was made passes equally when the check
happens early and when it happens late. A test that asserts no out-of-scope URL
was ever *queued* only passes when it happens early. So the property is checked
here, and `test_dast.py` asserts on the queue.

**Budget is finite.** A refused request still costs a scope decision and, if it
got as far as the transport, a budget reservation. A crawl of a site that links
to a thousand external URLs should not spend its budget discovering that they are
all out of scope.

So: `check` runs on every candidate before `_enqueue` accepts it, the decision's
own rule name is recorded, and the refusal is reported as a finding rather than
silently dropped — an application linking somewhere the engagement does not cover
is worth a human's attention.

Everything that does reach the network goes through `GatedTransport` as usual.
The pre-queue check is an additional gate, never a replacement: the engine still
re-resolves DNS at send time, so a host that passed here and then rebinds is
still refused.
"""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Sequence
from urllib.parse import urljoin, urlsplit, urlunsplit

from app.core.dast.contract import (
    SKIP_EXTENSIONS,
    CrawledPage,
    CrawlLimits,
    CrawlOutcome,
    CrawlResult,
    DastTarget,
    RefusedUrl,
)
from app.core.scope.context import RunContext
from app.core.scope.dns import DnsResolver, SystemDnsResolver
from app.core.scope.engine import ScopeEngine
from app.core.scope.transport import GatedTransport, ScopeBlockedError

#: `href`/`src` extraction. Deliberately a regex and not an HTML parser: the
#: input is an adversarial response body, and a regex over a bounded prefix
#: cannot be made to allocate unboundedly or recurse the way a lenient DOM
#: parser can. It misses links a browser would find — recorded as a limitation
#: in `docs/dast.md` rather than papered over.
_LINK = re.compile(
    rb"""(?:href|src)\s*=\s*(?:"([^"]{1,2048})"|'([^']{1,2048})'|([^\s>"']{1,2048}))""",
    re.IGNORECASE,
)
_FORM_ACTION = re.compile(
    rb"""<form\b[^>]{0,4096}?\baction\s*=\s*(?:"([^"]{0,2048})"|'([^']{0,2048})')""",
    re.IGNORECASE | re.DOTALL,
)
_TITLE = re.compile(rb"<title[^>]{0,256}>(.{0,512}?)</title>", re.IGNORECASE | re.DOTALL)

#: Schemes worth following. Everything else — `mailto:`, `javascript:`, `data:`,
#: `tel:` — is dropped without a scope check, because there is no host to check
#: and no request to make.
_FOLLOWABLE_SCHEMES = frozenset({"http", "https", ""})


def normalize(base: str, raw: str) -> str | None:
    """Resolve a link against its page and reduce it to a comparable form.

    Returns `None` for anything not worth following. Normalization matters for
    correctness, not tidiness: without it `/a`, `/a#x` and `/a?` are three
    queue entries and three requests for one page.
    """
    candidate = raw.strip()
    if not candidate:
        return None

    scheme = urlsplit(candidate).scheme.lower()
    if scheme and scheme not in _FOLLOWABLE_SCHEMES:
        return None

    absolute = urljoin(base, candidate)
    parts = urlsplit(absolute)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    # Userinfo in a crawled link is refused outright rather than stripped: it is
    # a way to make a URL look like it points somewhere it does not, and the
    # scope engine refuses it too.
    if "@" in parts.netloc:
        return None

    path = parts.path or "/"
    if any(path.lower().endswith(ext) for ext in SKIP_EXTENSIONS):
        return None

    # Fragment dropped — it never reaches the server, so two URLs differing only
    # by fragment are one request.
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, parts.query, ""))


def extract_links(base: str, body: bytes, *, limit: int) -> list[str]:
    """In-page links, normalized, de-duplicated, in document order."""
    found: list[str] = []
    seen: set[str] = set()
    for match in _LINK.finditer(body):
        raw = next(group for group in match.groups() if group is not None)
        try:
            candidate = normalize(base, raw.decode("utf-8", errors="replace"))
        except ValueError:
            # A malformed URL from a hostile page is a dropped link, not a crash.
            continue
        if candidate and candidate not in seen:
            seen.add(candidate)
            found.append(candidate)
        if len(found) >= limit:
            break
    return found


def extract_forms(base: str, body: bytes, *, limit: int) -> list[str]:
    actions: list[str] = []
    seen: set[str] = set()
    for match in _FORM_ACTION.finditer(body):
        raw = next((group for group in match.groups() if group is not None), b"")
        try:
            candidate = normalize(base, raw.decode("utf-8", errors="replace")) or base
        except ValueError:
            continue
        if candidate not in seen:
            seen.add(candidate)
            actions.append(candidate)
        if len(actions) >= limit:
            break
    return actions


def extract_title(body: bytes) -> str:
    match = _TITLE.search(body)
    if match is None:
        return ""
    return " ".join(match.group(1).decode("utf-8", errors="replace").split())[:200]


class ScopedCrawler:
    """Breadth-first, bounded, and unable to queue an out-of-scope URL."""

    def __init__(
        self,
        *,
        transport: GatedTransport | None = None,
        engine: ScopeEngine | None = None,
        dns_resolver: DnsResolver | None = None,
    ) -> None:
        self._transport = transport or GatedTransport()
        # The same engine the transport uses, so the pre-queue decision and the
        # send-time decision cannot disagree about policy. They can still differ
        # in outcome — DNS is re-resolved later — and that is the point.
        self._engine = engine or ScopeEngine()
        # Passed explicitly rather than read off the transport: the pre-queue
        # check and the send-time check must resolve names the same way, and
        # reaching into the transport's internals to arrange that would break
        # the first time the transport changed.
        self._dns_resolver = dns_resolver or SystemDnsResolver()

    async def _permitted(self, ctx: RunContext, url: str) -> tuple[bool, str, str]:
        """Would the engine allow a GET of this URL, without spending budget?

        `explain` rather than `check`: this is a queueing decision, and reserving
        budget for a request that may never be made would let a page full of
        links exhaust the run.
        """
        decision = await self._engine.explain(
            ctx, dns_resolver=self._dns_resolver, method="GET", url=url
        )
        return decision.allowed, decision.rule, decision.reason

    async def crawl(self, ctx: RunContext, target: DastTarget) -> CrawlResult:
        limits: CrawlLimits = target.limits
        result = CrawlResult(seed=target.seed_url)

        queue: deque[tuple[str, int]] = deque()
        queued: set[str] = set()

        async def enqueue(raw: str, depth: int, *, discovered_on: str) -> None:
            """The only way a URL becomes work. Nothing bypasses this."""
            candidate = normalize(discovered_on or raw, raw)
            if candidate is None or candidate in queued:
                return
            if depth > limits.max_depth:
                return
            allowed, rule, reason = await self._permitted(ctx, candidate)
            # Budget and the kill switch are handled by the loop, not here.
            # Budget says "not now" and the kill switch says "stop"; neither
            # means "the engagement does not cover this", and filing an in-scope
            # URL under `refused` would misreport the engagement's boundary.
            # Queueing it instead leaves it in `unvisited`, which is the honest
            # coverage statement: a page we did not get to.
            deferred = rule.startswith("budget_exceeded") or rule in ("kill_switch", "halted")
            if not allowed and not deferred:
                result.refused.append(
                    RefusedUrl(url=candidate, rule=rule, reason=reason, discovered_on=discovered_on)
                )
                return
            queued.add(candidate)
            queue.append((candidate, depth))

        for seed in (target.seed_url, *target.extra_seeds):
            await enqueue(seed, 0, discovered_on="")

        # Checked before the loop as well as inside it: a run halted before the
        # first fetch must report `HALTED`, not `EXHAUSTED`. An empty queue and
        # a stopped run look identical from inside the loop, and reporting
        # "exhausted" would claim the crawl finished.
        if ctx.halted or ctx.kill_switch.tripped:
            result.outcome = CrawlOutcome.HALTED
            result.unvisited = [url for url, _ in queue]
            return result

        while queue:
            if ctx.halted or ctx.kill_switch.tripped:
                result.outcome = CrawlOutcome.HALTED
                break
            if len(result.pages) >= limits.max_pages:
                result.outcome = CrawlOutcome.PAGE_LIMIT
                break

            url, depth = queue.popleft()
            try:
                observation = await self._transport.send(
                    ctx, method="GET", url=url, timeout_seconds=15.0
                )
            except ScopeBlockedError as exc:
                # It passed the pre-queue check and is refused now: DNS moved,
                # or budget ran out. Either way it is recorded, not retried.
                if exc.decision.rule.startswith("budget_exceeded"):
                    result.outcome = CrawlOutcome.BUDGET_EXHAUSTED
                    # Put it back before breaking. It was popped, so without
                    # this the page the crawl was about to fetch when budget ran
                    # out disappears from `unvisited` and coverage is overstated
                    # by exactly one page.
                    queue.appendleft((url, depth))
                    break
                result.refused.append(
                    RefusedUrl(
                        url=url,
                        rule=exc.decision.rule,
                        reason=exc.decision.reason,
                        discovered_on="(at send time)",
                    )
                )
                continue
            except Exception:  # noqa: BLE001 - one unreachable page is not a failed crawl
                continue

            body = observation.body[: limits.max_body_bytes]
            content_type = observation.headers.get("content-type", "")
            is_html = "html" in content_type.lower() or (not content_type and b"<" in body[:512])

            links = extract_links(url, body, limit=limits.max_links_per_page) if is_html else []
            forms = extract_forms(url, body, limit=limits.max_links_per_page) if is_html else []
            result.pages.append(
                CrawledPage(
                    url=url,
                    status_code=observation.status_code,
                    content_type=content_type,
                    depth=depth,
                    links=tuple(links),
                    forms=tuple(forms),
                    title=extract_title(body) if is_html else "",
                )
            )

            for link in links:
                await enqueue(link, depth + 1, discovered_on=url)

        result.unvisited = [url for url, _ in queue]
        return result


def state_changing_forms(result: CrawlResult) -> tuple[str, ...]:
    """Form actions found during the crawl, de-duplicated.

    Reported for review; **never submitted** unless `allow_state_mutation` is
    set, and this engine does not submit them even then — it records them for
    the adapters and for a human.
    """
    seen: list[str] = []
    for page in result.pages:
        for action in page.forms:
            if action not in seen:
                seen.append(action)
    return tuple(seen)


def refused_hosts(result: CrawlResult) -> tuple[str, ...]:
    hosts: list[str] = []
    for item in result.refused:
        host = urlsplit(item.url).hostname or ""
        if host and host not in hosts:
            hosts.append(host)
    return tuple(hosts)


def all_queued_urls(result: CrawlResult) -> tuple[str, ...]:
    """Every URL the crawl treated as work: visited plus still-queued.

    Exposed for the acceptance test, which asserts on this rather than on the
    requests actually made — see the module docstring.
    """
    return (*result.urls, *result.unvisited)


def seeds_from(urls: Sequence[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(url for url in urls if url))
