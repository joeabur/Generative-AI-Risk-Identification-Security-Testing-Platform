"""A deterministic provider for tests and CI
(Implementation Specification §20: "Do not consume paid AI API tokens during
normal test execution. Create a deterministic fake AI provider for CI.").

Deterministic means the same prompt always yields the same reply, derived
from the prompt itself. That makes assistant behaviour assertable — a test
can state exactly what it expects — and it means CI never depends on a
provider being reachable, or on a model's mood.

It also lets the adversarial tests be written honestly: the injection tests
do not check that a *model* resisted an instruction, which no test could
guarantee, but that the service never handed the model instructions it
should not have, and never acted on model output it should not act on.
"""

import hashlib
import json
from collections.abc import Callable
from typing import Any

from app.core.assistant.provider import Completion, parse_structured


class FakeProvider:
    """Records what it was asked, and answers predictably."""

    def __init__(
        self,
        *,
        name: str = "fake",
        model: str = "fake-model-1",
        responder: Callable[[str, str | None], str] | None = None,
    ) -> None:
        self.name = name
        self.model = model
        self._responder = responder
        # Every (system, prompt) pair this provider was given. The assistant
        # security tests assert on this: what reached the model is the thing
        # that matters, not what the model said back.
        self.calls: list[tuple[str | None, str]] = []

    async def generate(self, prompt: str, *, system: str | None = None) -> Completion:
        self.calls.append((system, prompt))
        text = (
            self._responder(prompt, system)
            if self._responder is not None
            else self._default_text(prompt)
        )
        return Completion(
            text=text,
            model=self.model,
            tokens_sent=len(prompt) // 4,
            tokens_received=len(text) // 4,
        )

    async def structured_output(
        self, prompt: str, *, schema: dict[str, Any], system: str | None = None
    ) -> tuple[dict[str, Any], Completion]:
        self.calls.append((system, prompt))
        if self._responder is not None:
            text = self._responder(prompt, system)
        else:
            text = json.dumps(
                {
                    key: f"deterministic {key} for {self._digest(prompt)}"
                    for key in schema.get("required", ["summary"])
                }
            )
        completion = Completion(
            text=text,
            model=self.model,
            tokens_sent=len(prompt) // 4,
            tokens_received=len(text) // 4,
        )
        return parse_structured(text, schema), completion

    @staticmethod
    def _digest(prompt: str) -> str:
        return hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:12]

    def _default_text(self, prompt: str) -> str:
        return f"deterministic response for {self._digest(prompt)}"
