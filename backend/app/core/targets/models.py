"""Shared adapter-layer types (docs/BUILD_SPEC.md §8).

`Observation` in the spec's domain model (§5) is the *transport-level*
request/response pair, which `app/core/scope/transport.py` already produces.
`TargetResponse` here wraps that with the adapter-level interpretation of it:
the extracted assistant text and any provider-reported token usage. Keeping
them separate means a probe can always fall back to the raw exchange when an
adapter's extraction misses.
"""

from dataclasses import dataclass, field
from typing import Any

from app.core.scope.transport import Observation


@dataclass(frozen=True)
class Turn:
    """One message sent to a target."""

    content: str
    role: str = "user"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Capabilities:
    """What a given target supports, so probes can skip what it cannot do
    rather than reporting a false negative (§9: `requires: Capabilities`)."""

    streaming: bool = False
    tools: bool = False
    multi_turn: bool = False
    system_prompt_control: bool = False


@dataclass(frozen=True)
class TokenUsage:
    """Provider-reported usage. Distinct from the tokenizer estimate in
    `tokens.py` — §6.2 requires using reported usage when available and only
    falling back to an estimate otherwise."""

    tokens_sent: int
    tokens_received: int


@dataclass(frozen=True)
class TargetResponse:
    observation: Observation
    text: str | None = None
    usage: TokenUsage | None = None
