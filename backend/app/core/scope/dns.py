import asyncio
import ipaddress
import socket
from typing import Protocol

IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class DnsResolver(Protocol):
    async def resolve(self, hostname: str) -> list[IpAddress]: ...


class SystemDnsResolver:
    """Resolves via the OS resolver, off the event loop thread.

    Deliberately does not cache: docs/BUILD_SPEC.md §6.2 requires re-checking
    DNS on every request specifically to catch a host's records changing
    between requests within the same run (DNS rebinding).
    """

    async def resolve(self, hostname: str) -> list[IpAddress]:
        loop = asyncio.get_running_loop()
        infos = await loop.run_in_executor(
            None, socket.getaddrinfo, hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
        seen: dict[str, IpAddress] = {}
        for _family, _type, _proto, _canonname, sockaddr in infos:
            ip_str = sockaddr[0]
            addr = ipaddress.ip_address(ip_str)
            seen[str(addr)] = addr
        return list(seen.values())
