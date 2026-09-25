"""Reading declared dependencies and runtimes out of a workspace.

Shared by the licence, EOL and name-confusion engines, which otherwise would
each grow their own half-correct parser.

Two deliberate limits, because both change what the findings may claim:

* **Declared, not resolved.** These parsers read what a manifest *says*.
  They do not run a resolver, so a transitive dependency that no manifest
  names is not seen. Every engine here reports on the declared set and says so;
  `pip-audit` is the engine that resolves.
* **Best-effort parsing, reported as such.** A `pyproject.toml` with a dynamic
  dependency table, or a `package.json` built by a script, yields fewer entries
  than really exist. An engine must never present a short list as a complete
  one.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from app.core.appsec.workspace import Workspace


@dataclass(frozen=True)
class Dependency:
    """One declared dependency.

    `version_spec` is the raw specifier as written (`>=2.1`, `^4.17.21`), not a
    resolved version: resolving is a different engine's job and pretending
    otherwise would put an unverified version number in a finding.
    """

    ecosystem: str
    name: str
    version_spec: str
    manifest: str


@dataclass(frozen=True)
class RuntimeDeclaration:
    """A runtime version the project pins, and where it was found."""

    runtime: str
    version: str
    source: str
    raw: str


# `name[extra]>=1.2,<2` — the name is everything before the first specifier,
# extra or marker character.
_PY_REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")
_PY_VERSION_SPEC = re.compile(r"^[<>=!~^]")

# `FROM python:3.9-slim AS builder` — the tag is what tells us the runtime.
_DOCKER_FROM = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?(?P<image>[^\s]+)(?:\s+AS\s+\S+)?\s*$",
    re.IGNORECASE,
)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _requirement_line(line: str, manifest: str) -> Dependency | None:
    stripped = line.split("#", 1)[0].strip()
    if not stripped or stripped.startswith("-"):
        # `-r other.txt`, `--index-url ...`: directives, not dependencies.
        return None
    match = _PY_REQUIREMENT.match(stripped)
    if match is None:
        return None
    name = match.group(1)
    rest = (match.group(3) or "").strip()
    spec = rest if _PY_VERSION_SPEC.match(rest) else ""
    return Dependency(ecosystem="pypi", name=name, version_spec=spec, manifest=manifest)


def python_dependencies(workspace: Workspace) -> list[Dependency]:
    found: list[Dependency] = []
    for path in workspace.files:
        relative = str(path.relative_to(workspace.root))
        if path.name in {"requirements.txt", "requirements.in"} or (
            path.name.startswith("requirements") and path.suffix in {".txt", ".in"}
        ):
            for line in _read(path).splitlines():
                dependency = _requirement_line(line, relative)
                if dependency is not None:
                    found.append(dependency)
        elif path.name == "pyproject.toml":
            try:
                data = tomllib.loads(_read(path))
            except tomllib.TOMLDecodeError:
                continue
            project = data.get("project", {})
            entries = project.get("dependencies", []) if isinstance(project, dict) else []
            optional = project.get("optional-dependencies", {}) if isinstance(project, dict) else {}
            for group in optional.values() if isinstance(optional, dict) else []:
                if isinstance(group, list):
                    entries = [*entries, *group]
            for entry in entries:
                if isinstance(entry, str):
                    dependency = _requirement_line(entry, relative)
                    if dependency is not None:
                        found.append(dependency)
    return found


def npm_dependencies(workspace: Workspace) -> list[Dependency]:
    found: list[Dependency] = []
    for path in workspace.files:
        if path.name != "package.json":
            continue
        relative = str(path.relative_to(workspace.root))
        try:
            data = json.loads(_read(path))
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            entries = data.get(section)
            if not isinstance(entries, dict):
                continue
            for name, spec in entries.items():
                found.append(
                    Dependency(
                        ecosystem="npm",
                        name=str(name),
                        version_spec=str(spec),
                        manifest=relative,
                    )
                )
    return found


def declared_dependencies(workspace: Workspace) -> list[Dependency]:
    return [*python_dependencies(workspace), *npm_dependencies(workspace)]


def _split_image(image: str) -> tuple[str, str]:
    """`python:3.9-slim` -> `("python", "3.9-slim")`.

    A digest pin (`image@sha256:…`) carries no version, and a registry host
    with a port (`registry:5000/app`) must not have its port read as a tag —
    hence splitting on the last `/` first.
    """
    reference = image.split("@", 1)[0]
    tail = reference.rsplit("/", 1)[-1]
    if ":" in tail:
        name, tag = tail.rsplit(":", 1)
        prefix = reference[: len(reference) - len(tail)]
        return prefix + name, tag
    return reference, ""


#: Base images whose tag is a runtime version we can reason about. An image not
#: listed here is still reported as a base image; it is just not claimed to be
#: a particular runtime.
_RUNTIME_IMAGES = {
    "python": "python",
    "node": "node",
    "golang": "go",
    "openjdk": "java",
    "eclipse-temurin": "java",
    "ruby": "ruby",
    "php": "php",
    "debian": "debian",
    "ubuntu": "ubuntu",
    "alpine": "alpine",
}

_VERSION_PREFIX = re.compile(r"^v?(\d+(?:\.\d+)*)")


def _version_of(tag: str) -> str:
    match = _VERSION_PREFIX.match(tag)
    return match.group(1) if match else ""


def base_images(workspace: Workspace) -> list[tuple[str, str, str]]:
    """`(image_reference, tag, manifest)` for every `FROM` in the workspace.

    Multi-stage builds produce several; all are returned, because a build stage
    with an ancient base still executes during the build.
    """
    images: list[tuple[str, str, str]] = []
    for path in workspace.files:
        if not (path.name == "Dockerfile" or path.name.startswith("Dockerfile.")):
            continue
        relative = str(path.relative_to(workspace.root))
        for line in _read(path).splitlines():
            match = _DOCKER_FROM.match(line)
            if match is None:
                continue
            image = match.group("image")
            if image.lower() == "scratch":
                continue
            name, tag = _split_image(image)
            images.append((name, tag, relative))
    return images


def runtime_declarations(workspace: Workspace) -> list[RuntimeDeclaration]:
    """Every runtime version the project pins, from any file that pins one."""
    declarations: list[RuntimeDeclaration] = []

    for name, tag, manifest in base_images(workspace):
        short = name.rsplit("/", 1)[-1]
        version = _version_of(tag)
        if not version:
            # A digest pin or a floating tag (`latest`) declares no version, so
            # there is nothing to compare against a support schedule.
            continue
        # An unrecognised image still yields a declaration, under its own short
        # name. Skipping it would make the base image invisible to the
        # end-of-life engine, and silence there reads as "supported" — the one
        # failure that engine exists to prevent. Instead it comes through with a
        # runtime the table has no row for, and is reported as not assessed.
        declarations.append(
            RuntimeDeclaration(
                runtime=_RUNTIME_IMAGES.get(short, short),
                version=version,
                source=manifest,
                raw=f"{name}:{tag}",
            )
        )

    for path in workspace.files:
        relative = str(path.relative_to(workspace.root))
        text = _read(path).strip()
        if path.name == ".python-version" and text:
            version = _version_of(text.splitlines()[0].strip())
            if version:
                declarations.append(
                    RuntimeDeclaration("python", version, relative, text.splitlines()[0].strip())
                )
        elif path.name == ".nvmrc" and text:
            version = _version_of(text.splitlines()[0].strip())
            if version:
                declarations.append(
                    RuntimeDeclaration("node", version, relative, text.splitlines()[0].strip())
                )
        elif path.name == "go.mod":
            for line in text.splitlines():
                if line.startswith("go "):
                    version = _version_of(line[3:].strip())
                    if version:
                        declarations.append(
                            RuntimeDeclaration("go", version, relative, line.strip())
                        )
                    break
        elif path.name == "package.json":
            try:
                data = json.loads(text or "{}")
            except json.JSONDecodeError:
                continue
            engines = data.get("engines") if isinstance(data, dict) else None
            node = engines.get("node") if isinstance(engines, dict) else None
            if isinstance(node, str):
                version = _version_of(node.lstrip("^~>=< "))
                if version:
                    declarations.append(RuntimeDeclaration("node", version, relative, node))

    return declarations
