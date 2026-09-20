"""Deciding which requests need a CSRF token, and checking it.

The decision is the whole control. Get the *scope* wrong in either direction
and you have either a broken product or an unprotected one:

* require a token on **Bearer-authenticated** requests and every CLI
  invocation, every CI gate and every API client breaks — and they were never
  at risk, because a cross-site page cannot attach an `Authorization` header to
  a request the browser sends on its own;
* skip the check on **cookie-authenticated** requests and the browser attaches
  the session for the attacker, which is the entire attack.

So the rule is: an unsafe method, authenticated by cookie, needs a token.
Nothing else does. `tests/security/test_csrf.py` asserts both halves, because
a control that is merely *present* is not the same as one applied where it
matters.

## Safe methods are exempt, and that is not an oversight

`GET`, `HEAD` and `OPTIONS` are exempt because they are required to be
side-effect-free. That is a real assumption, so it is enforced elsewhere rather
than hoped for: every route on the dashboard is a `GET`
(`tests/test_web.py::test_every_dashboard_route_is_a_get`) and the API's
state-changing routes all use unsafe methods, which the authorization matrix
enumerates. A `GET` that mutated would slip past this check, which is why that
test exists.
"""

from __future__ import annotations

from fastapi import HTTPException, Request, status

from app.core.config import get_settings
from app.core.csrf.tokens import verify

#: Methods that must not change state, and therefore need no token.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})

#: The cookie the token is published in, and the header it comes back in.
#: The cookie is deliberately **not** `httponly`: the page has to read it to
#: echo it back. That is safe because the token authenticates nothing on its
#: own — it proves only that the request came from a page able to read this
#: site's cookies.
COOKIE_NAME = "aegis_csrf"
HEADER_NAME = "X-CSRF-Token"
#: Server-rendered forms cannot set a header, so a field is accepted too.
FORM_FIELD = "csrf_token"

#: Routes that cannot carry a token because no session exists yet. Recorded
#: here, with reasons, rather than as scattered `if` statements.
#:
#: `login` and `register` are the classic "login CSRF" exposure: an attacker
#: can forge a request that signs a victim into the *attacker's* account, so
#: subsequent actions are recorded against it. This is accepted rather than
#: unnoticed — `docs/csrf.md` says so, and the mitigation (a pre-session token)
#: is a stated deferral. `logout` is exempt for the opposite reason: forcing a
#: victim to log out is an annoyance, not a compromise, and requiring a token
#: would mean a stale page could not log someone out.
EXEMPT_PATHS = frozenset(
    {
        "/api/v1/auth/login",
        "/api/v1/auth/register",
        "/api/v1/auth/logout",
    }
)


def authenticated_by_cookie(request: Request) -> bool:
    """True when the browser, not the caller, supplied the credential.

    An `Authorization` header is attached deliberately by client code; a
    cookie is attached by the browser on any request to this origin. Only the
    second is forgeable from another site, so only the second needs a token.
    """
    header = request.headers.get("Authorization", "")
    if header.lower().startswith("bearer "):
        return False
    return bool(request.cookies.get(get_settings().session_cookie_name))


def token_from(request: Request, form_value: str | None = None) -> str | None:
    return request.headers.get(HEADER_NAME) or form_value


def requires_token(request: Request) -> bool:
    if request.method.upper() in SAFE_METHODS:
        return False
    if request.url.path in EXEMPT_PATHS:
        return False
    return authenticated_by_cookie(request)


def check(request: Request, form_value: str | None = None) -> None:
    """Raise 403 unless this request carries a token valid for its session.

    The message names the header, because a developer who gets this wrong
    needs to know what to send and no attacker learns anything from it.
    """
    settings = get_settings()
    if not settings.csrf_protection_enabled or not requires_token(request):
        return

    session_value = request.cookies.get(settings.session_cookie_name)
    if not verify(
        token_from(request, form_value), session_value, secret=settings.effective_csrf_secret
    ):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail=(
                "Missing or invalid CSRF token. Cookie-authenticated requests that "
                f"change state must send the {HEADER_NAME} header (or a "
                f"{FORM_FIELD!r} form field) matching the {COOKIE_NAME!r} cookie."
            ),
        )
