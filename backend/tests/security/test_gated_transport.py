"""Transport-level scope tests: redirect handling and the deny-blocks-send
guarantee. docs/BUILD_SPEC.md §6.2 ("redirect to off-scope host -> BLOCKED
+ finding", "never auto-follow redirects").
"""

import pytest
import respx
from httpx import Response

from app.core.scope.engine import ScopeEngine
from app.core.scope.transport import GatedTransport, ScopeBlockedError
from tests.security.conftest import FakeDnsResolver, make_context, make_roe


async def test_denied_request_never_touches_the_network(fake_dns: FakeDnsResolver) -> None:
    transport = GatedTransport(engine=ScopeEngine(), dns_resolver=fake_dns)
    ctx = make_context()

    with respx.mock(assert_all_called=False) as router:
        route = router.get("https://evil.test/api").mock(return_value=Response(200))

        with pytest.raises(ScopeBlockedError) as exc_info:
            await transport.send(ctx, method="GET", url="https://evil.test/api")

        assert route.call_count == 0
    assert exc_info.value.decision.rule == "domain_not_allowlisted"


async def test_allowed_request_is_actually_sent(fake_dns: FakeDnsResolver) -> None:
    transport = GatedTransport(engine=ScopeEngine(), dns_resolver=fake_dns)
    ctx = make_context()

    with respx.mock() as router:
        router.get("https://ai.example.test/api").mock(
            return_value=Response(200, json={"ok": True})
        )
        observation = await transport.send(ctx, method="GET", url="https://ai.example.test/api")

    assert observation.status_code == 200
    assert observation.blocked_redirect_location is None


async def test_redirect_to_off_scope_host_is_not_followed_and_flagged(
    fake_dns: FakeDnsResolver,
) -> None:
    fake_dns.set("evil.test", ["203.0.113.99"])
    transport = GatedTransport(engine=ScopeEngine(), dns_resolver=fake_dns)
    ctx = make_context()

    with respx.mock(assert_all_called=False) as router:
        origin_route = router.get("https://ai.example.test/api").mock(
            return_value=Response(302, headers={"Location": "https://evil.test/steal"})
        )
        off_scope_route = router.get("https://evil.test/steal").mock(return_value=Response(200))

        observation = await transport.send(ctx, method="GET", url="https://ai.example.test/api")

        assert origin_route.call_count == 1
        assert off_scope_route.call_count == 0  # never followed

    assert observation.status_code == 302
    assert observation.blocked_redirect_location == "https://evil.test/steal"
    assert observation.blocked_redirect_decision is not None
    assert observation.blocked_redirect_decision.allowed is False
    assert observation.blocked_redirect_decision.rule == "domain_not_allowlisted"


async def test_redirect_to_in_scope_host_still_not_auto_followed(fake_dns: FakeDnsResolver) -> None:
    transport = GatedTransport(engine=ScopeEngine(), dns_resolver=fake_dns)
    ctx = make_context(roe=make_roe(allowed_paths=()))  # any path under the domain is fine

    with respx.mock(assert_all_called=False) as router:
        origin_route = router.get("https://ai.example.test/old").mock(
            return_value=Response(301, headers={"Location": "https://ai.example.test/new"})
        )
        target_route = router.get("https://ai.example.test/new").mock(return_value=Response(200))

        observation = await transport.send(ctx, method="GET", url="https://ai.example.test/old")

        assert origin_route.call_count == 1
        assert target_route.call_count == 0  # transport itself never follows, in-scope or not

    assert observation.status_code == 301
    assert observation.blocked_redirect_decision is not None
    assert observation.blocked_redirect_decision.allowed is True
