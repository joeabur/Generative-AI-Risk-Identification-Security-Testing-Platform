"""What a rate limit is, and the decisions it can reach.

§18 requires login rate limiting and §22 per-route rate limiting. This module
holds the shapes; `policy.py` holds the numbers and `window.py` the arithmetic,
so the part that decides can be tested without a clock or a Redis.

## Throttle, never lock out

A `Decision` says "not yet, try again in N seconds" and the window expires on
its own. There is deliberately no lockout state and no administrative unlock,
because an account lockout triggered by failed attempts is a denial-of-service
primitive aimed at whoever the attacker names: knowing a colleague's email
would be enough to keep them out. Throttling costs an attacker the same time
and costs the victim a wait that ends by itself.

## Failing open is the deliberate choice here

Every other boundary in this platform fails **closed** — the scope engine, the
authorization check, the gate. This one does not, and the asymmetry is
reasoned rather than convenient.

A rate limiter is a *mitigation layered on top of* authentication, not the
thing that decides whether a credential is valid. Argon2id still stands behind
it, and a correct password is still required. If the counter store is
unreachable and this failed closed, a Redis blip would lock every user out of
the product — trading a bounded, already-mitigated risk for a total outage.

So an unavailable store **allows the request and says so loudly**: the decision
records `degraded=True`, the caller logs it at error level and writes an audit
event. Silence would be the real failure; an operator who never learns their
rate limiting stopped working has a control that exists only on paper.
`docs/security-review.md` states this where a reader deciding whether to deploy
will see it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol


class Dimension(StrEnum):
    """What a bucket counts against.

    Two dimensions, because each alone is bypassable:

    * `IP` alone is defeated by a botnet — a thousand hosts each making three
      attempts against one account is a thousand times the budget.
    * `IDENTITY` alone is defeated by spraying — one host trying one common
      password against ten thousand accounts never exceeds any account's
      budget.

    Together they bound both shapes. An attempt consumes from both.
    """

    IP = "ip"
    IDENTITY = "identity"


@dataclass(frozen=True)
class Rule:
    """A budget: `limit` events per `window_seconds`, per key.

    `name` appears in logs and audit records, never the key itself — a key
    derived from an email address is a low-entropy identifier that does not
    belong in a log line.
    """

    name: str
    dimension: Dimension
    limit: int
    window_seconds: int

    def __post_init__(self) -> None:
        if self.limit < 1:
            raise ValueError(f"rule {self.name!r} has a limit below 1, which blocks everything")
        if self.window_seconds < 1:
            raise ValueError(f"rule {self.name!r} has a window below one second")


@dataclass(frozen=True)
class Decision:
    """Whether the request proceeds, and what to tell the caller.

    `retry_after_seconds` is what goes in the `Retry-After` header. It is the
    time until the window rolls over, not a fixed penalty, so a client that
    waits exactly that long succeeds rather than being punished again.
    """

    allowed: bool
    rule_name: str = ""
    remaining: int = 0
    retry_after_seconds: int = 0
    #: True when the store could not be reached and the request was allowed
    #: without being counted. Never silently discarded — see the module
    #: docstring for why failing open is right here and why saying so matters.
    degraded: bool = False

    @property
    def enforced(self) -> bool:
        """Whether this decision reflects a real count."""
        return not self.degraded


class RateLimitStore(Protocol):
    """A counter with an expiry. Two operations, both atomic.

    Deliberately tiny. A store that could do more would invite the policy to
    live inside it, and the policy is the part worth testing without a Redis.
    """

    async def incr(self, key: str, window_seconds: int) -> int:
        """Increment `key`, setting its expiry on first use. Returns the count.

        Raises `StoreUnavailable` when the backing store cannot be reached, so
        the caller can distinguish "over the limit" from "could not tell".
        """
        ...

    async def ttl(self, key: str) -> int:
        """Seconds until `key` expires, or 0 when it does not exist."""
        ...

    async def reset(self, key: str) -> None:
        """Forget `key`. Used when an attempt succeeds."""
        ...


class StoreUnavailable(RuntimeError):
    """The counter store could not be reached.

    Its own type rather than a bare exception, because the caller has to tell
    it apart from a limit being exceeded: one allows the request and flags the
    degradation, the other refuses.
    """
