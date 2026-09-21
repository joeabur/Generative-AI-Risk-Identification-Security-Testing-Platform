"""What a revocation store does, and the one place this control fails closed.

## This is an authorization decision, not a mitigation

`app/core/ratelimit/contract.py` fails **open** on an unreachable store, and
says explicitly why: a rate limiter sits on top of authentication, Argon2id
still stands behind it, and a Redis blip must not lock every user out of the
product.

Revocation is a different kind of control. It **is** the authorization
decision for a token that was deliberately killed — a logout, a suspected
compromise, a password reset. If the store cannot be consulted, this platform
does not know whether the token in hand is one of the ones that was killed,
and "we could not tell, so we let it through" is exactly the failure a
revoked-but-still-working token represents. So this boundary fails **closed**,
matching every other authorization decision on this platform: the scope
engine, `require_membership`, the CI gate.

The operational cost is real and is accepted deliberately: if the revocation
store is unreachable, every JWT-authenticated request is refused, not only the
ones that would have been revoked. That is a wider outage than the rate
limiter's failure mode risks, and it is the correct trade for what this
control is *for* — see `docs/revocation.md` for the reasoning written out for
someone deciding whether to deploy this.

API keys are unaffected either way: they have their own revocation
(`ApiKey.usable_at()`), checked from Postgres, and never touch this store.
"""

from __future__ import annotations

from typing import Protocol


class RevocationStore(Protocol):
    """A deny-list keyed by JWT id (`jti`), with per-entry expiry.

    Two operations. A store that could do more would invite policy into the
    store, and the policy — what triggers a revocation, how long an entry
    needs to live — belongs in `dependency.py`, testable without a Redis.
    """

    async def revoke(self, jti: str, ttl_seconds: int) -> None:
        """Deny `jti` for `ttl_seconds`.

        The TTL is the token's own remaining lifetime, never longer: an entry
        that outlived the token it revokes would grow the store forever for no
        benefit, since the token could not have been presented after it
        expired anyway.
        """
        ...

    async def is_revoked(self, jti: str) -> bool:
        """Whether `jti` is on the deny-list right now.

        Raises `RevocationStoreUnavailable` when the store cannot be reached,
        so the caller can fail closed rather than silently reading "not
        revoked" from a store that was never actually asked.
        """
        ...


class RevocationStoreUnavailable(RuntimeError):
    """The store could not be reached. Distinct from "not revoked".

    A caller that conflated the two would read a Redis outage as "nothing is
    revoked", which is precisely the false negative this whole module exists
    to prevent.
    """
