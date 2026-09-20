"""Supply-chain engines: licences, end-of-life runtimes, name confusion.

These engines answer questions an advisory database cannot, which also means
there is no CVE to check them against. So the tests are mostly about restraint:
that an unknown licence is not called permissive, that an unlisted runtime is
not called supported, and that a name-similarity signal is never presented as
malware.
"""

from datetime import date
from pathlib import Path

import pytest

from app.core.appsec.container.trivy_engine import ContainerScanEngine
from app.core.appsec.registry import appsec_engines
from app.core.appsec.supplychain.eol import AS_OF, is_end_of_life, lookup
from app.core.appsec.supplychain.eol_engine import EndOfLifeRuntimeEngine
from app.core.appsec.supplychain.license_engine import LicenseRiskEngine
from app.core.appsec.supplychain.licenses import LicenseRisk, classify, from_classifier
from app.core.appsec.supplychain.manifests import (
    Dependency,
    base_images,
    declared_dependencies,
    runtime_declarations,
)
from app.core.appsec.supplychain.typosquat import edit_distance, near_matches, unpinned
from app.core.appsec.supplychain.typosquat_engine import NameConfusionEngine
from app.core.appsec.workspace import CodeScope, resolve_workspace
from app.core.probes.models import Confidence, ScanResult, Severity

REPOS = Path(__file__).parent / "lab" / "repos"
SCOPE = CodeScope(allowed_paths=("src/**", "infra/**", "requirements.txt", ".python-version"))


def workspace(repo: str = "supplychain"):
    return resolve_workspace(REPOS / repo, SCOPE, build_manifest_paths=("requirements.txt",))


def ids(results: list[ScanResult]) -> set[str]:
    return {result.id for result in results}


# --- manifest parsing --------------------------------------------------------


def test_declared_dependencies_are_read_from_both_ecosystems() -> None:
    found = declared_dependencies(workspace())
    by_name = {dependency.name: dependency for dependency in found}
    assert by_name["requests"].ecosystem == "pypi"
    assert by_name["requests"].version_spec == "==2.32.3"
    assert by_name["1odash"].ecosystem == "npm"
    # A comment line is not a dependency.
    assert not any(name.startswith("#") for name in by_name)


def test_every_from_is_captured_including_a_later_build_stage() -> None:
    images = {(name, tag) for name, tag, _ in base_images(workspace())}
    assert ("python", "3.8-slim") in images
    assert ("crystal", "1.9-alpine") in images


@pytest.mark.parametrize(
    ("image", "expected"),
    [
        ("python:3.12-slim", ("python", "3.12-slim")),
        # A registry port must not be read as a tag.
        ("registry.internal:5000/app", ("registry.internal:5000/app", "")),
        ("registry.internal:5000/app:v2", ("registry.internal:5000/app", "v2")),
        # A digest pin carries no version.
        ("python@sha256:abc123", ("python", "")),
    ],
)
def test_image_references_are_split_correctly(image: str, expected: tuple[str, str]) -> None:
    from app.core.appsec.supplychain.manifests import _split_image

    assert _split_image(image) == expected


def test_runtime_declarations_come_from_every_file_that_pins_one() -> None:
    declarations = {
        (item.runtime, item.version, Path(item.source).name)
        for item in runtime_declarations(workspace())
    }
    assert ("python", "3.8", "Dockerfile") in declarations
    assert ("python", "3.10.14", ".python-version") in declarations


# --- end of life -------------------------------------------------------------


async def test_eol_findings_state_when_the_table_was_compiled() -> None:
    results = await EndOfLifeRuntimeEngine().run(workspace())
    eol = [result for result in results if result.id == "AEGIS-SUPPLY-010"]
    assert eol, ids(results)
    finding = next(result for result in eol if "3.8" in result.title)
    # Both dates must be present: "EOL on X" without "as of Y" leaves a reader
    # unable to tell stale data from a current answer.
    assert "2024-10-07" in finding.description
    assert AS_OF.isoformat() in finding.description
    assert "devguide.python.org" in finding.evidence


async def test_a_runtime_outside_the_table_is_reported_as_not_assessed() -> None:
    """Absence of data must never read as support."""
    results = await EndOfLifeRuntimeEngine().run(workspace())
    not_assessed = [result for result in results if result.id == "AEGIS-SUPPLY-019"]
    assert not_assessed, ids(results)
    assert "crystal" in not_assessed[0].evidence
    assert "not a statement that they are" in not_assessed[0].description
    assert not_assessed[0].confidence is Confidence.DESIGN_REVIEW


async def test_a_runtime_within_a_year_of_eol_is_informational() -> None:
    results = await EndOfLifeRuntimeEngine().run(workspace())
    approaching = [result for result in results if result.id == "AEGIS-SUPPLY-011"]
    assert approaching, ids(results)
    assert approaching[0].severity is Severity.INFORMATIONAL


async def test_an_eol_runtime_is_never_reported_as_critical() -> None:
    """A standing exposure is not a demonstrated exploit.

    §11 reserves the top band for what was shown to work; calling every old
    base image critical devalues the findings that are.
    """
    results = await EndOfLifeRuntimeEngine().run(workspace())
    assert all(result.severity is not Severity.CRITICAL for result in results)


def test_eol_severity_grows_with_age() -> None:
    from app.core.appsec.supplychain.eol_engine import _severity

    assert _severity(10) is Severity.LOW
    assert _severity(200) is Severity.MEDIUM
    assert _severity(900) is Severity.HIGH


def test_a_version_matches_its_series_not_a_shorter_prefix() -> None:
    """`3.9.18` must match the `3.9` row, never the `3` one."""
    entry = lookup("python", "3.9.18")
    assert entry is not None
    assert entry.series == "3.9"
    assert lookup("python", "3.99") is None
    assert lookup("rust", "1.70") is None


def test_eol_comparison_uses_an_injected_date_so_tests_are_not_time_bombs() -> None:
    entry = lookup("python", "3.13")
    assert entry is not None
    assert not is_end_of_life(entry, today=date(2026, 1, 1))
    assert is_end_of_life(entry, today=date(2030, 1, 1))


# --- licences ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("MIT", LicenseRisk.PERMISSIVE),
        ("Apache-2.0", LicenseRisk.PERMISSIVE),
        ("LGPL-2.1-only", LicenseRisk.WEAK_COPYLEFT),
        ("GPL-3.0-or-later", LicenseRisk.STRONG_COPYLEFT),
        ("AGPL-3.0", LicenseRisk.NETWORK_COPYLEFT),
        ("(MIT AND BSD-3-Clause)", LicenseRisk.PERMISSIVE),
        # The stricter reading of an OR, because nobody has recorded making the
        # permissive choice.
        ("MIT OR GPL-3.0", LicenseRisk.STRONG_COPYLEFT),
        ("WTFPL", LicenseRisk.PROPRIETARY_OR_UNKNOWN),
        ("", LicenseRisk.PROPRIETARY_OR_UNKNOWN),
        (None, LicenseRisk.PROPRIETARY_OR_UNKNOWN),
    ],
)
def test_licence_expressions_classify_by_their_strictest_component(
    expression: str | None, expected: LicenseRisk
) -> None:
    assert classify(expression) is expected


def test_a_missing_licence_is_never_treated_as_permission() -> None:
    assert classify(None) is LicenseRisk.PROPRIETARY_OR_UNKNOWN
    assert classify("   ") is LicenseRisk.PROPRIETARY_OR_UNKNOWN


def test_trove_classifiers_map_to_spdx_rather_than_being_trimmed() -> None:
    """Reading classifier prose literally put every such package in "unknown".

    This is the regression that mistake left behind.
    """
    assert from_classifier("License :: OSI Approved :: Apache Software License") == "Apache-2.0"
    assert from_classifier("License :: OSI Approved :: BSD License") == "BSD-3-Clause"
    assert classify(from_classifier("License :: OSI Approved :: MIT License")) is (
        LicenseRisk.PERMISSIVE
    )
    assert from_classifier("License :: Invented :: Nonsense") is None


async def test_network_copyleft_is_reported_and_permissive_is_not() -> None:
    licences = {
        "aegis-fixture-agpl": "AGPL-3.0",
        "requests": "Apache-2.0",
        "1odash": "MIT",
        "exprses": "MIT",
        "some-internal-lib": "MIT",
    }
    engine = LicenseRiskEngine(lookup=lambda _workspace, dependency: licences.get(dependency.name))
    results = await engine.run(workspace())
    assert "AEGIS-SUPPLY-020" in ids(results)
    finding = next(result for result in results if result.id == "AEGIS-SUPPLY-020")
    assert "aegis-fixture-agpl" in finding.evidence
    # No finding per MIT dependency: that is noise which buries the one above.
    assert "requests" not in finding.evidence
    assert "AEGIS-SUPPLY-021" not in ids(results)


async def test_a_licence_finding_reports_an_obligation_not_a_violation() -> None:
    engine = LicenseRiskEngine(lookup=lambda _w, _d: "AGPL-3.0")
    finding = next(
        result for result in await engine.run(workspace()) if result.id == "AEGIS-SUPPLY-020"
    )
    assert "not a finding that it has been breached" in finding.description
    assert "violation" not in finding.title.lower()
    # Not a security exposure, and the finding says so.
    assert "not a security exposure" in finding.impact


async def test_an_undeterminable_licence_is_reported_as_unknown() -> None:
    engine = LicenseRiskEngine(lookup=lambda _w, _d: None)
    results = await engine.run(workspace())
    unknown = next(result for result in results if result.id == "AEGIS-SUPPLY-023")
    assert unknown.confidence is Confidence.DESIGN_REVIEW
    assert "absence of a grant" in unknown.description
    assert "not stated" in unknown.evidence


# --- name confusion ----------------------------------------------------------


@pytest.mark.parametrize(
    ("ecosystem", "name", "should_match"),
    [
        ("npm", "1odash", True),
        ("pypi", "reqeusts", True),
        ("pypi", "urllib4", True),
        ("pypi", "python-requests", True),
        ("pypi", "requests", False),
        ("npm", "lodash", False),
        # A real package whose name is a prefix of another real one. Flagging
        # this would be the false positive that makes the check unusable.
        ("pypi", "dateutil", False),
        ("pypi", "cryptography", False),
    ],
)
def test_name_similarity_flags_impersonations_and_not_real_packages(
    ecosystem: str, name: str, should_match: bool
) -> None:
    matches = near_matches(Dependency(ecosystem, name, "", "manifest"))
    assert bool(matches) is should_match, matches


def test_a_transposition_is_caught_although_levenshtein_scores_it_as_two() -> None:
    assert edit_distance("reqeusts", "requests", cap=1) > 1
    assert near_matches(Dependency("pypi", "reqeusts", "", "m"))


def test_edit_distance_stops_at_the_cap() -> None:
    assert edit_distance("a", "abcdefgh", cap=3) == 4
    assert edit_distance("kitten", "sitting", cap=3) == 3


@pytest.mark.parametrize(
    ("spec", "expected"), [("", True), ("*", True), ("latest", True), ("^1.2", False)]
)
def test_unpinned_recognises_the_wildcards(spec: str, expected: bool) -> None:
    assert unpinned(Dependency("npm", "x", spec, "m")) is expected


async def test_name_confusion_findings_never_claim_malware() -> None:
    results = await NameConfusionEngine().run(workspace())
    assert "AEGIS-SUPPLY-030" in ids(results)
    for result in results:
        blob = f"{result.title} {result.description} {result.impact}".lower()
        assert "malicious package" not in blob
        assert "malware" not in blob
        # A manifest reading, not a demonstration.
        assert result.confidence is Confidence.DESIGN_REVIEW
        assert result.severity in {Severity.LOW, Severity.INFORMATIONAL}


async def test_unpinned_and_install_hooks_are_reported_separately() -> None:
    results = await NameConfusionEngine().run(workspace())
    assert "AEGIS-SUPPLY-031" in ids(results)
    assert "AEGIS-SUPPLY-032" in ids(results)
    unpinned_finding = next(r for r in results if r.id == "AEGIS-SUPPLY-031")
    assert "some-internal-lib" in unpinned_finding.evidence
    hook = next(r for r in results if r.id == "AEGIS-SUPPLY-032")
    assert "postinstall" in hook.evidence


async def test_name_confusion_says_it_consulted_no_registry() -> None:
    """Without a registry lookup, dependency confusion cannot be established,
    and the finding must not imply it was."""
    results = await NameConfusionEngine().run(workspace())
    finding = next(result for result in results if result.id == "AEGIS-SUPPLY-030")
    assert "No registry was consulted" in finding.description


# --- container ---------------------------------------------------------------


async def test_the_container_engine_only_applies_where_an_image_is_built() -> None:
    engine = ContainerScanEngine()
    assert engine.applies_to(workspace())
    assert not engine.applies_to(workspace("vulnerable"))


async def test_the_container_engine_states_that_base_layers_were_not_scanned() -> None:
    """A filesystem scan that reported clean would otherwise read as "the image
    is clean", when the layers under the application were never looked at."""
    from app.core.appsec.tooling import tool_available

    results = await ContainerScanEngine().run(workspace())
    if not tool_available("trivy"):
        # Absent tool: a visible gap, not an empty result set.
        assert ids(results) == {"AEGIS-APPSEC-000"}
        return
    gap = next(result for result in results if result.id == "AEGIS-CONTAINER-009")
    assert "did not pull or examine" in gap.description
    assert "python:3.8-slim" in gap.evidence


# --- registry ----------------------------------------------------------------


def test_the_new_engines_are_registered() -> None:
    registered = {engine.meta.id for engine in appsec_engines()}
    assert {
        "appsec.supplychain.eol",
        "appsec.supplychain.license",
        "appsec.supplychain.name_confusion",
        "appsec.container.trivy",
    } <= registered


def test_no_supply_chain_engine_reaches_the_network() -> None:
    """Three of the four are file-only by design, and the fourth runs its tool
    offline. Pinned because adding a lookup would be a disclosure decision, not
    an implementation detail."""
    import inspect

    from app.core.appsec.supplychain import eol_engine, license_engine, typosquat_engine

    for module in (eol_engine, license_engine, typosquat_engine):
        source = inspect.getsource(module)
        assert "run_tool" not in source, module.__name__
        assert "GatedTransport" not in source, module.__name__

    trivy = inspect.getsource(ContainerScanEngine)
    assert "--skip-db-update" in trivy
    assert "--offline-scan" in trivy
    assert "NetworkUse.OFFLINE" in trivy
