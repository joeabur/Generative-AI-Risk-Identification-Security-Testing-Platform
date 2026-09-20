"""The §23 workflow set, asserted against the files on disk.

`docs/BUILD_SPEC.md` §23 names nine workflows. Two of them went unwritten for
five phases while `docs/security-review.md` carried a row saying so — which
worked, but only because somebody kept remembering to update that row. This
enumerates instead.

It also asserts two properties §23 states in one line and which are easy to
lose one workflow at a time: least-privilege `permissions:` blocks, and no
`pull_request_target` (which runs with the base repository's secrets against a
fork's code — the classic CI takeover).
"""

from __future__ import annotations

import pathlib
from typing import Any

import pytest
import yaml

WORKFLOWS = pathlib.Path(__file__).resolve().parents[2] / ".github" / "workflows"

#: Every workflow §23 names, and what each is for. Absence is a test failure,
#: so a deferral has to be an explicit edit here rather than a quiet omission.
REQUIRED = {
    "ci.yml": "lint, types, tests, coverage",
    "security.yml": "Semgrep, Bandit, Gitleaks, detect-secrets",
    "codeql.yml": "CodeQL",
    "deps.yml": "pip-audit, npm audit, OSV",
    "container.yml": "Trivy over the built images",
    "sbom.yml": "CycloneDX SBOM",
    "lab-e2e.yml": "a real assessment against the demo lab",
    "framework-drift.yml": "weekly upstream framework version check",
    "release.yml": "signed artifacts and provenance",
}


def _load(name: str) -> dict[Any, Any]:
    document = yaml.safe_load((WORKFLOWS / name).read_text())
    assert isinstance(document, dict), f"{name} is not a mapping"
    return document


@pytest.mark.parametrize("name", sorted(REQUIRED))
def test_every_workflow_the_spec_names_exists(name: str) -> None:
    path = WORKFLOWS / name
    assert path.is_file(), f"{name} is missing — §23 requires it for {REQUIRED[name]}"
    # A file that exists but does nothing is worse than one that is absent,
    # because the absence would at least be visible.
    document = _load(name)
    assert document.get("jobs"), f"{name} declares no jobs"


@pytest.mark.parametrize("name", sorted(REQUIRED))
def test_every_workflow_declares_its_permissions(name: str) -> None:
    """§23: least-privilege `permissions:` blocks.

    GitHub's default grant is broad and repository-wide. A workflow that says
    nothing inherits it, so "we use least privilege" has to mean every file
    states what it needs.

    Verified by deleting the top-level `permissions:` from `codeql.yml`.
    """
    document = _load(name)
    top_level = document.get("permissions")
    job_level = [job.get("permissions") for job in document.get("jobs", {}).values()]
    assert top_level is not None or all(item is not None for item in job_level), (
        f"{name} declares no permissions, so it inherits the repository default. "
        "Every workflow states what it needs."
    )


@pytest.mark.parametrize("name", sorted(REQUIRED))
def test_no_workflow_uses_pull_request_target(name: str) -> None:
    """`pull_request_target` runs a fork's code with this repository's secrets.

    It is the standard way a CI system gets taken over by a pull request, and
    there is no use for it here: nothing in this repository needs a fork's PR
    to have write access or secrets.
    """
    document = _load(name)
    # `on:` parses as the boolean True in YAML 1.1 — a real trap, since a test
    # that looked up the string key would silently check nothing.
    triggers = document.get("on", document.get(True, {}))
    names = set(triggers) if isinstance(triggers, dict | list) else {triggers}
    assert "pull_request_target" not in names, (
        f"{name} uses pull_request_target, which runs a fork's code with this repository's secrets."
    )


def test_the_release_workflow_signs_what_it_publishes() -> None:
    """A release that attaches unsigned artifacts is an unsigned release.

    §23 asks for Sigstore signing and provenance attestation. This checks the
    signing step and the `id-token: write` permission it needs are both
    present, because either one alone is a release that does not actually sign.
    """
    document = _load("release.yml")
    body = (WORKFLOWS / "release.yml").read_text()

    assert "sigstore" in body.lower(), "release.yml does not sign anything"
    assert "attest-build-provenance" in body, "release.yml attests no provenance"

    build = document["jobs"]["build"]
    assert build["permissions"].get("id-token") == "write", (
        "keyless Sigstore signing needs `id-token: write`; without it the signing "
        "step fails and a release could be published unsigned."
    )


def test_the_drift_workflow_does_not_fetch_inside_the_checker() -> None:
    """The fetching stays in the job, not in the Python that compares.

    Every outbound request in the application goes through the scope engine's
    transport. A maintenance script that opened its own connection would be a
    second HTTP path, placed just outside the directory the static check scans
    — which is worse than an obvious one, because it looks compliant.

    Verified by adding `import httpx` to the checker and watching this fail.
    """
    checker = (
        pathlib.Path(__file__).resolve().parents[1] / "scripts" / "framework_drift.py"
    ).read_text()
    for library in ("httpx", "requests", "urllib.request", "urllib3", "aiohttp"):
        assert f"import {library}" not in checker, (
            f"scripts/framework_drift.py imports {library}. The fetch belongs in the "
            "workflow, where it is visible in the job log; this module compares."
        )

    body = (WORKFLOWS / "framework-drift.yml").read_text()
    assert "gh api" in body, "the drift workflow reads no upstream versions"
    assert "framework_drift" in body, "the drift workflow never runs the checker"
