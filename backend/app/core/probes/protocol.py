"""Probe contract and registry (docs/BUILD_SPEC.md §9, §10, §16).

A probe is given a read-only view of the target's surface, the run context,
and the gated transport. It may only reach the network through that
transport, so every request it makes is scope-checked, budget-counted and
cancellable like any other — a probe cannot widen its own scope, which is
also what makes the plugin system of §16 safe to open up later.
"""

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from app.core.discovery.openapi import DiscoveredOperation
from app.core.probes.credentials import AuthorizationTestPlan
from app.core.probes.models import ScanResult
from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport


@dataclass(frozen=True)
class ProbeTarget:
    """What a probe is allowed to know about the target.

    Only enabled operations appear in `operations`: the surface toggle is an
    operator's decision about what to touch, and a probe never sees what it
    was told to leave alone. Credentials are `CredentialSet` values resolved
    from the environment at run time, never read from the database.
    """

    base_url: str
    operations: tuple[DiscoveredOperation, ...] = ()
    safe_mode: bool = True
    authorization: AuthorizationTestPlan = field(default_factory=AuthorizationTestPlan)


@runtime_checkable
class Probe(Protocol):
    id: str
    version: str
    name: str

    def applies_to(self, target: ProbeTarget) -> bool:
        """Cheap pre-flight: may this probe run at all against this target?

        Answering `False` here is how a probe declines without spending a
        request, so that a run's budget is not consumed proving that, for
        example, a target exposes no GraphQL endpoint.
        """
        ...

    async def run(
        self, target: ProbeTarget, ctx: RunContext, transport: GatedTransport
    ) -> list[ScanResult]: ...


class ProbeRegistry:
    """The set of probes a run may draw from.

    Registration is explicit rather than import-scanning: a probe that is
    not deliberately registered does not run, which is the property the
    plugin allowlist in §16 depends on.
    """

    def __init__(self) -> None:
        self._probes: dict[str, Probe] = {}

    def register(self, probe: Probe) -> None:
        if probe.id in self._probes:
            raise ValueError(f"probe id {probe.id!r} is already registered")
        self._probes[probe.id] = probe

    def get(self, probe_id: str) -> Probe:
        return self._probes[probe_id]

    def all(self) -> list[Probe]:
        return [self._probes[probe_id] for probe_id in sorted(self._probes)]

    def applicable(self, target: ProbeTarget) -> list[Probe]:
        return [probe for probe in self.all() if probe.applies_to(target)]

    def __len__(self) -> int:
        return len(self._probes)

    def __contains__(self, probe_id: object) -> bool:
        return probe_id in self._probes
