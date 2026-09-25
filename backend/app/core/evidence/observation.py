"""Turning a gated request into a sealed evidence bundle
(docs/BUILD_SPEC.md §13).

`GatedTransport` has always returned a full `Observation` — method, URL,
status, headers, timing, body — and its own docstring promised that the
`Observation` → sealed bundle pipeline would arrive. This is it. Until it
existed, only the AI engine's findings carried downloadable evidence, and an
API finding's evidence was a sentence of prose that nobody could verify and
no retest could compare against.

Everything still goes through `build_bundle`, so a bundle made here is
redacted on exactly the same terms as one made anywhere else. Nothing in this
module reproduces that logic.
"""

from app.core.evidence.bundle import EvidenceBundle, build_bundle
from app.core.scope.transport import Observation


def bundle_from_observation(
    observation: Observation,
    *,
    probe_id: str,
    probe_version: str,
    verdict: str,
    request_headers: dict[str, str] | None = None,
    request_body: str = "",
    canaries: tuple[str, ...] = (),
    include_body: bool = False,
) -> EvidenceBundle:
    """One request/response exchange, sealed.

    `include_body` is off by default, and the default is the interesting
    part. Several probes establish an *authorization decision* — a BOLA probe
    proves that account B got a success for account A's object — and for
    those the response body is another party's data. Storing it would make
    the evidence bundle a copy of the records the probe was only supposed to
    prove were reachable. So a body is kept only where a caller says the body
    *is* the finding (an error page leaking a stack trace, a response echoing
    an injected marker), and otherwise the bundle says plainly that it was
    deliberately not retained.

    A refused redirect is recorded in `adapter` rather than dropped: "the
    target tried to send us somewhere the scope engine would not follow" is
    part of what happened, and a reader who cannot see it would wonder why
    the response looks truncated.
    """
    adapter: dict[str, object] = {"transport": "gated_http"}
    if observation.blocked_redirect_location is not None:
        adapter["blocked_redirect_location"] = observation.blocked_redirect_location
    if observation.blocked_redirect_decision is not None:
        adapter["blocked_redirect_rule"] = observation.blocked_redirect_decision.rule

    return build_bundle(
        probe_id=probe_id,
        probe_version=probe_version,
        method=observation.method,
        url=observation.url,
        request_headers=request_headers,
        request_body=request_body,
        status_code=observation.status_code,
        response_headers=observation.headers,
        response_body=(
            observation.body.decode("utf-8", errors="replace")
            if include_body
            else (
                f"[NOT RETAINED] {len(observation.body)} byte body. This probe "
                "establishes an authorization or configuration decision, so the "
                "response content is not part of its evidence and was not stored."
            )
        ),
        timing_ms=observation.elapsed_ms,
        adapter=adapter,
        detector_verdict=verdict,
        canaries=canaries,
    )
