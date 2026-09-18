from app.core.scope.hostmatch import normalize_hostname


def test_normalize_hostname_empty_string_returns_empty() -> None:
    assert normalize_hostname("") == ""
    assert normalize_hostname("   ") == ""


def test_normalize_hostname_falls_back_to_lowercased_raw_on_invalid_idna() -> None:
    # A label starting with a hyphen is invalid IDNA — normalize_hostname
    # must fail closed to a safe string (never raise) rather than crash the
    # request through to the scope engine's internal-error path.
    assert normalize_hostname("-BAD-.Test") == "-bad-.test"


def test_normalize_hostname_lowercases_and_strips_trailing_dot() -> None:
    assert normalize_hostname("AI.Example.Test.") == "ai.example.test"
