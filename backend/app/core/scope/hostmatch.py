"""Hostname, path, and IP allow/deny matching — no I/O, pure functions."""

import ipaddress
from collections.abc import Sequence

import idna

_BLOCKED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
)

# Cloud metadata endpoints — always blocked unless explicitly allowlisted,
# even though some (169.254.169.254) already fall inside a blocked network
# above; kept as an explicit, named set per docs/BUILD_SPEC.md §6.2.
_METADATA_IPS: frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address] = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("fd00:ec2::254"),
    }
)


def normalize_hostname(host: str) -> str:
    """ASCII/punycode-normalize a hostname so homograph unicode domains
    compare correctly against plain-ASCII allowlist patterns instead of
    matching (or mismatching) on raw, unnormalized unicode."""
    host = host.strip().rstrip(".").lower()
    if not host:
        return host
    try:
        return idna.encode(host, uts46=True).decode("ascii").lower()
    except (idna.IDNAError, UnicodeError):
        # Not valid IDNA (e.g. already-invalid input) — compare as-is rather
        # than raising, so an unmatchable hostname fails the allowlist check
        # cleanly instead of crashing the whole request through to the
        # fail-closed internal-error path.
        return host


def hostname_matches(host: str, pattern: str) -> bool:
    host_n = normalize_hostname(host)
    if pattern.startswith("*."):
        suffix = normalize_hostname(pattern[2:])
        return host_n == suffix or host_n.endswith("." + suffix)
    return host_n == normalize_hostname(pattern)


def hostname_matches_any(host: str, patterns: Sequence[str]) -> bool:
    return any(hostname_matches(host, pattern) for pattern in patterns)


def path_matches(path: str, pattern: str) -> bool:
    if pattern.endswith("/*"):
        prefix = pattern[:-1]  # keep the trailing slash
        return path == prefix.rstrip("/") or path.startswith(prefix)
    return path == pattern


def path_matches_any(path: str, patterns: Sequence[str]) -> bool:
    return any(path_matches(path, pattern) for pattern in patterns)


def is_blocked_ip(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    allowed_ranges: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> bool:
    is_sensitive = ip in _METADATA_IPS or any(ip in net for net in _BLOCKED_NETWORKS)
    if not is_sensitive:
        return False
    return not any(ip in net for net in allowed_ranges)


def parse_ip_ranges(
    ranges: Sequence[str],
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    return tuple(ipaddress.ip_network(r, strict=False) for r in ranges)
