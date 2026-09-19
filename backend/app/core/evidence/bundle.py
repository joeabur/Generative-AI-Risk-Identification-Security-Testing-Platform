"""Evidence bundles (docs/BUILD_SPEC.md §13).

A bundle is what lets someone else check a finding: the request, the
response, the timing, the probe and adapter that produced it, the detector's
verdict, and the canary values in play.

Three rules, in the order they matter:

* **Redaction runs before write.** Not before display, not before export —
  before the bytes reach disk. A tool that finds a leaked key and then
  writes it into an evidence file has multiplied the exposure it was hired
  to detect. `Authorization` headers and cookies are masked unconditionally,
  because they are credentials by definition and no detector needs to
  recognise them first.
* **Bundles are content-addressed.** The SHA-256 of the canonical bytes *is*
  the identifier, so a finding referencing a hash either resolves to exactly
  those bytes or does not resolve at all.
* **The manifest is hash-chained.** Each entry carries the previous entry's
  digest, so removing or altering a bundle after the fact breaks the chain
  at a detectable point rather than silently succeeding.
"""

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.core.redaction.secrets import SecretMatch, find_secrets, redact

# Masked whatever they contain. A detector that has to *recognise* a session
# cookie will eventually meet one it does not recognise; a header named
# `Authorization` is a credential by definition.
ALWAYS_MASKED_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "x-amz-security-token",
    }
)
MASK = "[REDACTED]"

MAX_BODY_CHARS = 64 * 1024


@dataclass(frozen=True)
class EvidenceBundle:
    """One reproducible observation, already redacted."""

    probe_id: str
    probe_version: str
    request: dict[str, Any]
    response: dict[str, Any]
    timing_ms: float
    adapter: dict[str, Any] = field(default_factory=dict)
    model_identifier: str | None = None
    detector_verdict: str = ""
    judge_transcript: str | None = None
    canaries: tuple[str, ...] = ()
    # What the redactor removed, described rather than reproduced: kind,
    # digest, masked preview and offset. Kept so a reader can see that
    # redaction happened and what it caught.
    redactions: tuple[dict[str, Any], ...] = ()
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def canonical_bytes(self) -> bytes:
        """Stable serialization — sorted keys, no incidental whitespace.

        The digest has to be reproducible from the same content, so key
        order and spacing cannot be allowed to change it.
        """
        return json.dumps(
            {
                "probe_id": self.probe_id,
                "probe_version": self.probe_version,
                "request": self.request,
                "response": self.response,
                "timing_ms": self.timing_ms,
                "adapter": self.adapter,
                "model_identifier": self.model_identifier,
                "detector_verdict": self.detector_verdict,
                "judge_transcript": self.judge_transcript,
                "canaries": list(self.canaries),
                "redactions": list(self.redactions),
                "created_at": self.created_at,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(self.canonical_bytes()).hexdigest()


def mask_headers(
    headers: dict[str, str], *, ignore: Sequence[str] = ()
) -> tuple[dict[str, str], list[SecretMatch]]:
    """Mask credential headers unconditionally, scan the rest.

    The header *name* is the signal for the first group. For everything else
    the value is scanned, because a secret can turn up in a header nobody
    thought of.
    """
    masked: dict[str, str] = {}
    found: list[SecretMatch] = []

    for name, value in headers.items():
        if name.strip().lower() in ALWAYS_MASKED_HEADERS:
            masked[name] = MASK
            continue
        result = redact(value, ignore=ignore)
        masked[name] = result.redacted_text
        found.extend(result.matches)
    return masked, found


def build_bundle(
    *,
    probe_id: str,
    probe_version: str,
    method: str,
    url: str,
    request_headers: dict[str, str] | None = None,
    request_body: str = "",
    status_code: int | None = None,
    response_headers: dict[str, str] | None = None,
    response_body: str = "",
    timing_ms: float = 0.0,
    adapter: dict[str, Any] | None = None,
    model_identifier: str | None = None,
    detector_verdict: str = "",
    judge_transcript: str | None = None,
    canaries: tuple[str, ...] = (),
) -> EvidenceBundle:
    """Assemble a bundle with everything redacted on the way in.

    There is deliberately no way to construct one from raw material without
    passing through here: an `EvidenceBundle` built by hand would skip the
    redaction this function exists to guarantee.
    """
    # This run's own markers are exempt everywhere: see `find_secrets`.
    request_masked, request_secrets = mask_headers(request_headers or {}, ignore=canaries)
    response_masked, response_secrets = mask_headers(response_headers or {}, ignore=canaries)

    request_redacted = redact(request_body[:MAX_BODY_CHARS], ignore=canaries)
    response_redacted = redact(response_body[:MAX_BODY_CHARS], ignore=canaries)
    judge_redacted = redact(judge_transcript, ignore=canaries) if judge_transcript else None
    # The detector's own words go through redaction too. Nothing guarantees a
    # detector kept only a digest — one that quoted what it saw would put a
    # disclosed credential into the bundle by a route redaction never covered.
    verdict_redacted = redact(detector_verdict, ignore=canaries)

    matches = [
        *request_secrets,
        *response_secrets,
        *request_redacted.matches,
        *response_redacted.matches,
        *(judge_redacted.matches if judge_redacted else []),
        *verdict_redacted.matches,
    ]

    return EvidenceBundle(
        probe_id=probe_id,
        probe_version=probe_version,
        request={
            "method": method,
            "url": redact(url).redacted_text,
            "headers": request_masked,
            "body": request_redacted.redacted_text,
        },
        response={
            "status_code": status_code,
            "headers": response_masked,
            "body": response_redacted.redacted_text,
        },
        timing_ms=timing_ms,
        adapter=adapter or {},
        model_identifier=model_identifier,
        detector_verdict=verdict_redacted.redacted_text,
        judge_transcript=judge_redacted.redacted_text if judge_redacted else None,
        canaries=canaries,
        redactions=tuple(match.as_dict() for match in matches),
    )


def secret_kinds(payload: bytes, *, ignore: Sequence[str] = ()) -> list[str]:
    """Which kinds of credential a byte string would still disclose.

    The kinds rather than a bare boolean, so a refusal can say what tripped
    it. "This bundle contains a secret" sends an operator hunting; "this
    bundle contains a high_entropy_string" tells them where to look.
    """
    text = payload.decode("utf-8", errors="replace")
    return sorted({match.kind for match in find_secrets(text, ignore=ignore)})


def contains_secret(payload: bytes, *, ignore: Sequence[str] = ()) -> bool:
    """Would this byte string still disclose a credential?

    Used by the property test that guards the invariant, and by the store
    as a last check before writing.
    """
    return bool(find_secrets(payload.decode("utf-8", errors="replace"), ignore=ignore))
