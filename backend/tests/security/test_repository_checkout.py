"""Repository checkout is a scope boundary (docs/BUILD_SPEC.md §6.3).

`git` does not route through `GatedTransport`, so the controls the transport
would apply are applied before it starts. A `repo_ref` is operator-supplied
and therefore untrusted input; without these checks it is a request-forgery
primitive aimed at whatever the worker can reach.
"""

import subprocess
from pathlib import Path

import pytest

from app.core.appsec.checkout import (
    CheckoutError,
    check_host_allowed,
    clone_repository,
    discard_checkout,
    make_checkout_dir,
    parse_repo_ref,
)

ALLOWED = ("github.com", "gitlab.com")


def _public(host: str) -> list[str]:
    return ["203.0.113.10"]


def test_a_git_plus_https_ref_is_parsed_into_url_and_revision() -> None:
    ref = parse_repo_ref("git+https://github.com/example/app.git#main")

    assert ref.scheme == "https"
    assert ref.host == "github.com"
    assert ref.url == "https://github.com/example/app.git"
    assert ref.revision == "main"


@pytest.mark.parametrize(
    "ref",
    [
        "ext::sh -c 'curl evil.test'",
        "git://github.com/example/app.git",
        "ssh://git@github.com/example/app.git",
        "file:///etc/../etc/shadow" if False else "unknown://github.com/x",
    ],
)
def test_schemes_that_execute_or_do_not_authenticate_are_refused(ref: str) -> None:
    """`ext::` turns a clone into arbitrary command execution and `git://`
    is unauthenticated plaintext. Neither is ever acceptable."""
    with pytest.raises(CheckoutError, match="not permitted"):
        parse_repo_ref(ref)


def test_inline_credentials_in_a_url_are_refused() -> None:
    """A URL with a password in it ends up in process listings and logs."""
    with pytest.raises(CheckoutError, match="inline credentials"):
        parse_repo_ref("https://user:secret@github.com/example/app.git")


def test_an_empty_host_allowlist_permits_nothing() -> None:
    """Fail closed. Treating "unstated" as "any host" would make repo_ref a
    way to reach anything the worker can reach."""
    ref = parse_repo_ref("https://github.com/example/app.git")

    with pytest.raises(CheckoutError, match="not a permissive one"):
        check_host_allowed(ref, (), resolver=_public)


def test_a_host_outside_the_allowlist_is_refused() -> None:
    ref = parse_repo_ref("https://evil.test/example/app.git")

    with pytest.raises(CheckoutError, match="not in code_scope.allowed_repo_hosts"):
        check_host_allowed(ref, ALLOWED, resolver=_public)


def test_a_lookalike_host_does_not_match_the_allowlist() -> None:
    """`github.com.evil.test` must not be treated as `github.com`."""
    ref = parse_repo_ref("https://github.com.evil.test/example/app.git")

    with pytest.raises(CheckoutError, match="not in code_scope.allowed_repo_hosts"):
        check_host_allowed(ref, ALLOWED, resolver=_public)


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "::1"],
)
def test_an_allowlisted_host_resolving_to_a_blocked_address_is_refused(address: str) -> None:
    """The name being approved is not enough: an approved name that points at
    loopback, a private range or the cloud metadata service is still refused,
    using the scope engine's own blocked ranges rather than a second list."""
    ref = parse_repo_ref("https://github.com/example/app.git")

    with pytest.raises(CheckoutError, match="blocked address"):
        check_host_allowed(ref, ALLOWED, resolver=lambda host: [address])


def test_an_allowlisted_public_host_is_permitted() -> None:
    ref = parse_repo_ref("https://github.com/example/app.git")

    check_host_allowed(ref, ALLOWED, resolver=_public)


def test_a_host_that_does_not_resolve_is_refused_rather_than_assumed_safe() -> None:
    ref = parse_repo_ref("https://github.com/example/app.git")

    with pytest.raises(CheckoutError, match="did not resolve"):
        check_host_allowed(ref, ALLOWED, resolver=lambda host: [])


def test_a_local_path_needs_no_host_allowlist() -> None:
    """A `file:` reference makes no network request, so the host rules do not
    apply to it."""
    ref = parse_repo_ref("file:///srv/checkouts/app")

    assert ref.is_local
    check_host_allowed(ref, (), resolver=_public)


def _make_origin(tmp_path: Path) -> Path:
    origin = tmp_path / "origin"
    origin.mkdir()
    (origin / "app.py").write_text("x = 1\n")
    for command in (
        ["git", "init", "--quiet", "-b", "main"],
        ["git", "config", "user.email", "lab@example.test"],
        ["git", "config", "user.name", "Lab"],
        ["git", "add", "."],
        ["git", "commit", "--quiet", "-m", "initial"],
    ):
        subprocess.run(command, cwd=origin, check=True, capture_output=True)
    return origin


async def test_cloning_a_local_repository_produces_a_working_checkout(
    tmp_path: Path,
) -> None:
    origin = _make_origin(tmp_path)
    destination = make_checkout_dir()
    try:
        await clone_repository(parse_repo_ref(f"file://{origin}"), destination / "repo")
        assert (destination / "repo" / "app.py").read_text() == "x = 1\n"
    finally:
        discard_checkout(destination)

    assert not destination.exists()


async def test_a_failed_clone_raises_rather_than_leaving_a_silent_gap(
    tmp_path: Path,
) -> None:
    destination = make_checkout_dir()
    try:
        with pytest.raises(CheckoutError, match="git clone failed"):
            await clone_repository(
                parse_repo_ref(f"file://{tmp_path / 'does-not-exist'}"), destination / "repo"
            )
    finally:
        discard_checkout(destination)


def test_discarding_a_checkout_is_idempotent() -> None:
    """Cleanup runs in a `finally` and must never mask the original error."""
    path = make_checkout_dir()
    discard_checkout(path)
    discard_checkout(path)

    assert not path.exists()


def test_the_clone_command_disables_repository_controlled_code() -> None:
    """Hooks, submodules and ext:: are the three ways a clone executes or
    fetches something the repository's author chose. Asserted on the command
    itself so a future edit that drops one of them fails here."""
    import inspect

    source = inspect.getsource(clone_repository)

    assert "core.hooksPath=/dev/null" in source
    assert "protocol.ext.allow=never" in source
    assert "--no-recurse-submodules" in source
    assert "GIT_TERMINAL_PROMPT" in source
