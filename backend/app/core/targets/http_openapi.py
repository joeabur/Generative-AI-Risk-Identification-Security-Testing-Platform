"""`http_openapi` — a generic REST surface driven by a parsed OpenAPI 3.x
document (docs/BUILD_SPEC.md §8).

A spec can declare any `servers[].url` it likes, including one pointing at a
host the operator never authorized. That is not this adapter's problem to
solve by second-guessing the document: every request it builds still goes
through `GatedTransport`, so an off-scope server URL is refused by the scope
engine exactly like any other out-of-scope request. The spec is treated as a
*hint about shape*, never as authorization.
"""

import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlencode, urljoin

from app.core.discovery.openapi import DiscoveredOperation, DiscoveredSurface
from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport
from app.core.targets.models import Capabilities, TargetResponse


class MissingPathParameterError(ValueError):
    """A templated path segment had no value supplied — sending the literal
    `{id}` to the target would silently test the wrong URL."""


@dataclass(frozen=True)
class HttpOpenApiConfig:
    base_url: str
    headers: dict[str, str] | None = None


class HttpOpenApiAdapter:
    id = "http_openapi"

    def __init__(
        self,
        config: HttpOpenApiConfig,
        surface: DiscoveredSurface,
        transport: GatedTransport | None = None,
    ) -> None:
        self._config = config
        self._surface = surface
        self._transport = transport or GatedTransport()

    async def capabilities(self) -> Capabilities:
        return Capabilities(
            streaming=False, tools=False, multi_turn=False, system_prompt_control=False
        )

    async def reset(self) -> None:
        return None

    def operations(self) -> list[DiscoveredOperation]:
        return list(self._surface.operations)

    async def send_operation(
        self,
        operation: DiscoveredOperation,
        ctx: RunContext,
        *,
        path_params: dict[str, str] | None = None,
        query_params: dict[str, str] | None = None,
        body: Any | None = None,
    ) -> TargetResponse:
        path = _fill_path(operation.path, path_params or {})
        url = urljoin(self._config.base_url, path.lstrip("/"))
        if query_params:
            url = f"{url}?{urlencode(query_params)}"

        headers = dict(self._config.headers or {})
        content: bytes | None = None
        if body is not None:
            headers.setdefault("Content-Type", "application/json")
            content = json.dumps(body).encode("utf-8")

        observation = await self._transport.send(
            ctx, method=operation.method, url=url, headers=headers, content=content
        )
        return TargetResponse(observation=observation)


def _fill_path(template: str, values: dict[str, str]) -> str:
    """Substitute `{param}` segments, URL-encoding each value.

    Encoding matters here beyond correctness: object IDs used in BOLA checks
    (§10) come from another account's data and must not be able to inject
    extra path segments into the request being authorized.
    """
    result = template
    start = result.find("{")
    while start != -1:
        end = result.find("}", start)
        if end == -1:
            break
        name = result[start + 1 : end]
        if name not in values:
            raise MissingPathParameterError(f"no value supplied for path parameter {name!r}")
        result = result[:start] + quote(str(values[name]), safe="") + result[end + 1 :]
        start = result.find("{")
    return result
