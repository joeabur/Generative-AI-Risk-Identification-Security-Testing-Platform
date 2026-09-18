"""Adapter protocols (docs/BUILD_SPEC.md §8).

The spec states one `TargetAdapter` protocol whose core method is
`send(turn, ctx)`. That shape fits a conversational target, but it does not
fit `http_openapi`, where the unit of work is "call operation X with
parameters", not "say something". Rather than inventing a fake `Turn` for a
REST call — which would make every REST probe pack and unpack a pretend
conversation — the protocol is split in two here, sharing the identity and
lifecycle methods the spec defines:

    TargetAdapter          id, capabilities(), reset()
    ├── ConversationalAdapter   send(turn, ctx)        chat_http, openai_compatible
    └── RestSurfaceAdapter      operations(), send_operation(...)   http_openapi

Every adapter sends exclusively through `GatedTransport`; none may construct
an HTTP client of its own, and `tests/security/test_scope_controls.py`
enforces that across the whole codebase.
"""

from typing import Any, Protocol, runtime_checkable

from app.core.discovery.openapi import DiscoveredOperation
from app.core.scope.context import RunContext
from app.core.targets.models import Capabilities, TargetResponse, Turn


@runtime_checkable
class TargetAdapter(Protocol):
    id: str

    async def capabilities(self) -> Capabilities: ...

    async def reset(self) -> None:
        """Clear any conversation/session state held by the adapter."""
        ...


@runtime_checkable
class ConversationalAdapter(TargetAdapter, Protocol):
    async def send(self, turn: Turn, ctx: RunContext) -> TargetResponse: ...


@runtime_checkable
class RestSurfaceAdapter(TargetAdapter, Protocol):
    def operations(self) -> list[DiscoveredOperation]: ...

    async def send_operation(
        self,
        operation: DiscoveredOperation,
        ctx: RunContext,
        *,
        path_params: dict[str, str] | None = None,
        query_params: dict[str, str] | None = None,
        body: Any | None = None,
    ) -> TargetResponse: ...
