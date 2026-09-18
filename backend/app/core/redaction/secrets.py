"""Secret detection and redaction (docs/BUILD_SPEC.md §9 LLM02, §13).

The rule this module exists to enforce: **a detected secret is never
persisted.** What gets stored is `sha256(secret)`, a masked preview, and
where in the text it was found. That is enough to prove the finding, to
deduplicate across runs, and to show an operator which credential to rotate
— and not enough to use the credential.

It matters because a tool that finds a leaked key and then writes it into a
findings table, an evidence file and a PDF report has multiplied the
exposure it was hired to detect.
"""

import hashlib
import math
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretMatch:
    """A detected secret, described without containing it."""

    kind: str
    sha256: str
    masked_preview: str
    offset: int
    length: int

    def as_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "sha256": self.sha256,
            "masked_preview": self.masked_preview,
            "offset": self.offset,
            "length": self.length,
        }


@dataclass(frozen=True)
class RedactionResult:
    redacted_text: str
    matches: tuple[SecretMatch, ...]

    @property
    def found(self) -> bool:
        return bool(self.matches)


# Patterns whose *shape* identifies the issuer, so a match is high-confidence
# without needing to see the value. Ordered longest-first where they could
# overlap, so the more specific rule wins.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe_key", re.compile(r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    (
        "connection_string",
        re.compile(r"\b(?:postgres|postgresql|mysql|mongodb|redis|amqp)://[^\s:@/]+:[^\s@]+@\S+"),
    ),
    (
        "assigned_credential",
        # `api_key = "..."`, `password: ...` — an assignment to a
        # credential-shaped name, which is how secrets appear in config that
        # a model has been shown.
        re.compile(
            r"\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd)"
            r"\s*[:=]\s*[\"']?([A-Za-z0-9/+_.-]{12,})[\"']?",
            re.IGNORECASE,
        ),
    ),
)

# Below this, a random-looking string is more likely an id or a hash than a
# credential. Tuned to sit above base64-ish identifiers and below real keys.
_ENTROPY_THRESHOLD = 4.2
_ENTROPY_MIN_LENGTH = 24
_ENTROPY_CANDIDATE = re.compile(r"\b[A-Za-z0-9+/=_-]{24,}\b")

MASK = "[REDACTED]"


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _digest(secret: str) -> str:
    return "sha256:" + hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _mask(secret: str) -> str:
    """Show enough to recognise which credential this is, and no more.

    Four leading characters identifies the issuer prefix (`AKIA`, `ghp_`)
    without being usable, and the length tells an operator whether they are
    looking at the key they think they are.
    """
    if len(secret) <= 8:
        return f"{'*' * len(secret)} ({len(secret)} chars)"
    return f"{secret[:4]}{'*' * 8} ({len(secret)} chars)"


def find_secrets(text: str) -> list[SecretMatch]:
    """Detect secrets in `text`, returning descriptions rather than values."""
    matches: list[SecretMatch] = []
    claimed: list[tuple[int, int]] = []

    def _overlaps(start: int, end: int) -> bool:
        return any(start < other_end and other_start < end for other_start, other_end in claimed)

    for kind, pattern in _PATTERNS:
        for match in pattern.finditer(text):
            # Where a pattern captures the value specifically (an assignment),
            # hash only the value — not the surrounding `api_key =`, which
            # would make identical secrets hash differently.
            start, end = match.span(1) if match.groups() else match.span()
            if _overlaps(start, end):
                continue
            secret = text[start:end]
            claimed.append((start, end))
            matches.append(
                SecretMatch(
                    kind=kind,
                    sha256=_digest(secret),
                    masked_preview=_mask(secret),
                    offset=start,
                    length=len(secret),
                )
            )

    for match in _ENTROPY_CANDIDATE.finditer(text):
        start, end = match.span()
        if _overlaps(start, end):
            continue
        candidate = match.group()
        if len(candidate) < _ENTROPY_MIN_LENGTH:
            continue
        if shannon_entropy(candidate) < _ENTROPY_THRESHOLD:
            continue
        claimed.append((start, end))
        matches.append(
            SecretMatch(
                kind="high_entropy_string",
                sha256=_digest(candidate),
                masked_preview=_mask(candidate),
                offset=start,
                length=len(candidate),
            )
        )

    return sorted(matches, key=lambda item: item.offset)


def redact(text: str) -> RedactionResult:
    """Replace every detected secret with a mask.

    Replacement runs back to front so that each earlier offset is still
    valid when it is used — doing it forwards would shift every subsequent
    match and corrupt the output.
    """
    matches = find_secrets(text)
    redacted = text
    for match in sorted(matches, key=lambda item: item.offset, reverse=True):
        redacted = redacted[: match.offset] + MASK + redacted[match.offset + match.length :]
    return RedactionResult(redacted_text=redacted, matches=tuple(matches))
