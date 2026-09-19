"""An OpenAI-compatible chat-completions provider
(Implementation Specification §9).

Speaks the shape that OpenAI, Azure OpenAI, vLLM, Ollama, llama.cpp and most
gateways all implement, which is why it is the one wire format worth
supporting: it covers hosted and self-hosted without a vendor SDK.

Every request goes through `GatedTransport` under `platform_egress_context`,
so the provider host is the only host this can reach.
"""

import json
from typing import Any

from app.core.assistant.egress import platform_egress_context
from app.core.assistant.provider import (
    Completion,
    ProviderConfig,
    ProviderError,
    parse_structured,
)
from app.core.scope.transport import GatedTransport, ScopeBlockedError


class OpenAICompatibleProvider:
    """Chat completions over the OpenAI-compatible wire format."""

    def __init__(
        self,
        config: ProviderConfig,
        transport: GatedTransport | None = None,
        *,
        api_key: str | None = None,
    ) -> None:
        self._config = config
        self._transport = transport or GatedTransport()
        # Resolved once, held in memory only, never written anywhere.
        self._api_key = api_key if api_key is not None else config.resolve_key()
        self.name = config.provider
        self.model = config.model

    async def generate(self, prompt: str, *, system: str | None = None) -> Completion:
        return await self._complete(prompt, system=system)

    async def structured_output(
        self, prompt: str, *, schema: dict[str, Any], system: str | None = None
    ) -> tuple[dict[str, Any], Completion]:
        instruction = (
            "Reply with a single JSON object and nothing else. Required fields: "
            + ", ".join(schema.get("required", []))
        )
        completion = await self._complete(
            prompt, system=f"{system}\n\n{instruction}" if system else instruction
        )
        return parse_structured(completion.text, schema), completion

    async def _complete(self, prompt: str, *, system: str | None) -> Completion:
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        body = json.dumps(
            {
                "model": self._config.model,
                "messages": messages,
                "max_tokens": self._config.max_output_tokens,
                "temperature": self._config.temperature,
            }
        ).encode("utf-8")

        try:
            observation = await self._transport.send(
                platform_egress_context(self._config),
                method="POST",
                url=self._config.endpoint,
                headers=headers,
                content=body,
                timeout_seconds=self._config.timeout_seconds,
            )
        except ScopeBlockedError as exc:
            # The provider endpoint failed the same checks a target would.
            # Reported rather than worked around: an endpoint resolving to a
            # blocked address is a configuration problem worth seeing.
            raise ProviderError(
                f"provider endpoint refused by the scope engine: {exc.decision.reason}"
            ) from exc
        except Exception as exc:  # noqa: BLE001 - surfaced as a provider error
            raise ProviderError(f"provider request failed: {exc}") from exc

        if observation.status_code >= 400:
            raise ProviderError(
                f"provider returned HTTP {observation.status_code}: "
                f"{observation.body[:300].decode('utf-8', errors='replace')}"
            )

        return self._parse(observation.body)

    def _parse(self, raw: bytes) -> Completion:
        try:
            payload = json.loads(raw)
        except ValueError as exc:
            raise ProviderError(f"provider response was not JSON: {exc}") from exc

        choices = payload.get("choices") or []
        if not choices:
            raise ProviderError("provider response contained no choices")
        text = str(choices[0].get("message", {}).get("content", ""))

        usage = payload.get("usage") or {}
        return Completion(
            text=text,
            model=str(payload.get("model", self._config.model)),
            tokens_sent=int(usage.get("prompt_tokens", 0) or 0),
            tokens_received=int(usage.get("completion_tokens", 0) or 0),
            # Cost is reported only where the provider reports it. An
            # estimate presented as a measurement is the kind of number that
            # ends up in a budget review as though it were real.
            cost_usd=None,
        )
