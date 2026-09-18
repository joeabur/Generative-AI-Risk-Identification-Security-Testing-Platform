"""SystemDnsResolver — exercised against a monkeypatched `socket.getaddrinfo`
rather than the real network, so this stays deterministic and offline."""

import socket

from app.core.scope.dns import SystemDnsResolver


async def test_system_dns_resolver_dedupes_and_parses_addresses(monkeypatch) -> None:
    def fake_getaddrinfo(host, port, family, socktype):
        assert host == "ai.example.test"
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.5", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.5", 0)),  # duplicate
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 0, 0, 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    resolver = SystemDnsResolver()
    ips = await resolver.resolve("ai.example.test")

    assert {str(ip) for ip in ips} == {"203.0.113.5", "2001:db8::1"}
