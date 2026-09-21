"""Server-side JWT revocation (docs/BUILD_SPEC.md §18: "session/token management").

A JWT is normally valid until it expires, full stop — there is no server-side
way to make one stop working early. That is fine until "logout" is asked to
mean something, or a token leaks and needs killing before its natural
12-hour lifetime runs out. This package is what makes both real.
"""
