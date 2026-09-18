"""Executable checks for an assessment run.

Phase 4 builds the *engine*; the AI and API probe catalogues (§9, §10) are
Phases 5–6. So the only check shipped here is a reachability probe, which is
deliberately not a security test: it issues one request per enabled endpoint
and records what came back. That is enough to exercise the whole lifecycle
end to end — scope checks, budgets, cancellation, progress — without
pre-empting the probe work, and it is genuinely useful on its own as a
pre-flight confirmation that a target is reachable and in scope.
"""

from dataclasses import dataclass
from typing import Protocol

from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport, ScopeBlockedError


@dataclass(frozen=True)
class CheckResult:
    check_id: str
    surface: str
    ok: bool
    detail: str
    status_code: int | None = None
    blocked_rule: str | None = None


class Check(Protocol):
    id: str
    name: str

    async def run(self, ctx: RunContext, transport: GatedTransport) -> list[CheckResult]: ...


@dataclass(frozen=True)
class Endpoint:
    method: str
    path: str


class ReachabilityCheck:
    """One request per enabled endpoint, recording status or the scope rule
    that refused it. A blocked request is a normal, recorded outcome — not
    an error — because "the scope engine refused this" is exactly the kind
    of thing an operator needs to see in the run log.
    """

    id = "core.reachability"
    name = "Endpoint reachability"

    def __init__(self, base_url: str, endpoints: list[Endpoint]) -> None:
        self._base_url = base_url
        self._endpoints = endpoints

    @property
    def endpoints(self) -> list[Endpoint]:
        return list(self._endpoints)

    async def run(self, ctx: RunContext, transport: GatedTransport) -> list[CheckResult]:
        results: list[CheckResult] = []
        for endpoint in self._endpoints:
            results.append(await self._probe_one(ctx, transport, endpoint))
            if ctx.halted:
                break
        return results

    async def _probe_one(
        self, ctx: RunContext, transport: GatedTransport, endpoint: Endpoint
    ) -> CheckResult:
        from urllib.parse import urljoin

        surface = f"{endpoint.method} {endpoint.path}"
        url = urljoin(self._base_url, endpoint.path.lstrip("/"))
        try:
            observation = await transport.send(ctx, method=endpoint.method, url=url)
        except ScopeBlockedError as exc:
            return CheckResult(
                check_id=self.id,
                surface=surface,
                ok=False,
                detail=exc.decision.reason,
                blocked_rule=exc.decision.rule,
            )
        except Exception as exc:  # noqa: BLE001 - a dead target is a result, not a crash
            return CheckResult(
                check_id=self.id, surface=surface, ok=False, detail=f"request failed: {exc}"
            )

        return CheckResult(
            check_id=self.id,
            surface=surface,
            ok=True,
            detail=f"responded with {observation.status_code}",
            status_code=observation.status_code,
        )
