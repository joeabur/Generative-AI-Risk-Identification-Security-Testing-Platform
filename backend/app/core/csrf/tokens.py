"""Issuing and verifying CSRF tokens.

§18 requires "CSRF protection where cookie-based sessions are used" and §22
repeats it for browser sessions. This platform has no server-side session
store — a JWT in a cookie is the whole session — so a synchronizer token with
server state would mean inventing that store just for this. A **signed
double-submit** gives the same guarantee without it.

## Plain double-submit is not enough, and the difference matters

The textbook version sets a random value in a cookie and requires the same
value in a header. It rests on an attacker not being able to read the cookie,
which same-origin policy provides — but *not* on an attacker being unable to
**write** one. Anything that can set a cookie for the site can set both halves:

* a sibling subdomain (`blog.example.com` setting a cookie for
  `.example.com`), which is a cookie-scoping quirk rather than an XSS;
* a MITM on a plain-HTTP subdomain, since cookies ignore the port and are only
  origin-bound by the `Secure` flag.

Either one defeats the naive scheme completely, because the attacker chooses
both values and they trivially match.

So the token here is **bound to the session it was issued for**: it carries an
HMAC over the session cookie's own value. An attacker who can plant cookies
still cannot produce a token that verifies against *the victim's* session,
because the HMAC needs the server's secret. Swapping in a token minted for a
different session fails for the same reason.

## Why it is not simply the session token again

Reusing the session value as the CSRF token would put a credential somewhere a
page's JavaScript must read it, which turns any content-injection bug into
session theft. The token here is derived, single-purpose, and useless for
authentication.
"""

from __future__ import annotations

import hmac
import secrets
from hashlib import sha256

#: Enough randomness that guessing is not a strategy, short enough to sit in a
#: cookie and a header without comment.
_NONCE_BYTES = 16

_SEPARATOR = "."


def _signature(nonce: str, session_value: str, secret: str) -> str:
    return hmac.new(
        secret.encode("utf-8"),
        f"{nonce}{_SEPARATOR}{session_value}".encode(),
        sha256,
    ).hexdigest()


def issue(session_value: str, *, secret: str) -> str:
    """A token valid only for `session_value`.

    The nonce makes each issued token distinct, so a token observed once (in a
    referrer, a log, a screenshot) is not the only token that will ever work
    and cannot be correlated across sessions.
    """
    nonce = secrets.token_urlsafe(_NONCE_BYTES)
    return f"{nonce}{_SEPARATOR}{_signature(nonce, session_value, secret)}"


def verify(token: str | None, session_value: str | None, *, secret: str) -> bool:
    """Whether `token` was issued for `session_value`.

    Returns False rather than raising on anything malformed: a caller that had
    to distinguish "absent", "wrong shape" and "bad signature" would be a
    caller with three chances to let one through, and the response is identical
    in every case anyway.
    """
    if not token or not session_value:
        return False

    nonce, separator, provided = token.partition(_SEPARATOR)
    if not separator or not nonce or not provided:
        return False

    expected = _signature(nonce, session_value, secret)
    # Constant time: a leaky comparison would let an attacker recover a valid
    # signature a byte at a time, which is the whole control.
    #
    # **No test covers this.** Replacing `compare_digest` with `==` keeps the
    # whole CSRF suite green, because a timing property is not observable from
    # a functional assertion. It is stated here rather than implied, so nobody
    # reads the passing suite as proof of it.
    return hmac.compare_digest(provided, expected)
