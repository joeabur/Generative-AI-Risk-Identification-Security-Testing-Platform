"""Redaction and judge invariants (docs/BUILD_SPEC.md §7.3, §9 LLM02, §13)."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.core.probes.ai.judge import (
    Calibration,
    JudgeConfig,
    JudgeNotCalibratedError,
)
from app.core.redaction.secrets import MASK, find_secrets, redact, shannon_entropy

SECRETS = [
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "xoxb-1234567890-abcdefghijkl",
    "sk-proj-abcdefghijklmnopqrstuvwxyz12",
    "-----BEGIN RSA PRIVATE KEY-----",  # pragma: allowlist secret
]


@pytest.mark.parametrize("secret", SECRETS)
def test_known_secret_shapes_are_detected_and_masked(secret: str) -> None:
    result = redact(f"the value is {secret} ok")

    assert result.found
    assert secret not in result.redacted_text
    assert MASK in result.redacted_text
    match = result.matches[0]
    assert match.sha256.startswith("sha256:")
    assert secret not in match.masked_preview


def test_the_same_secret_always_produces_the_same_digest() -> None:
    """Dedup across runs depends on this, and it must not depend on the
    surrounding text."""
    first = find_secrets(f"api_key = {SECRETS[0]}")[0]
    second = find_secrets(f"different context {SECRETS[0]} here")[0]

    assert first.sha256 == second.sha256


@given(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=300))
def test_redaction_never_leaves_a_detected_secret_behind(noise: str) -> None:
    """Property: whatever surrounds it, a detected secret does not survive
    redaction. This is the §13 invariant the whole evidence pipeline rests on."""
    text = f"{noise} {SECRETS[0]} {noise}"
    result = redact(text)

    if result.found:
        assert SECRETS[0] not in result.redacted_text


def test_ordinary_text_is_not_flagged() -> None:
    """False positives here are expensive: every one is an operator asked to
    rotate a credential that does not exist."""
    for benign in (
        "The order id is 12345 and the tracking code is AB-9981.",
        "Please see https://example.test/docs/getting-started for details.",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
        "commit 4f3a2b1c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a",
    ):
        assert redact(benign).found is False, benign


def test_entropy_rises_with_randomness() -> None:
    assert shannon_entropy("aaaaaaaaaaaaaaaa") < shannon_entropy("aB3xQ9zP1mK7wL2v")


def test_a_judge_cannot_be_enabled_without_calibration() -> None:
    """§7.3: "An uncalibrated judge does not ship." Enforced by the type, so
    there is no configuration in which one can be switched on."""
    with pytest.raises(JudgeNotCalibratedError, match="published precision and recall"):
        JudgeConfig(enabled=True)


def test_the_default_judge_is_disabled_and_says_so() -> None:
    config = JudgeConfig()

    assert config.enabled is False
    assert "Judge: disabled" in config.describe()
    # §14: what was not used is reported, not omitted.
    assert "deterministic detector" in config.describe()


def test_an_enabled_judge_publishes_its_numbers() -> None:
    config = JudgeConfig(
        enabled=True,
        calibration=Calibration(
            fixture_set="tests/fixtures/judge/v1",
            precision=0.91,
            recall=0.78,
            measured_at="2026-09-18",
            judge_model="example-judge-1",
        ),
    )

    described = config.describe()
    assert "precision 0.91" in described
    assert "recall 0.78" in described
