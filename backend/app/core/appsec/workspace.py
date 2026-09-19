"""Resolving a target's code scope to a set of files that may be scanned
(docs/BUILD_SPEC.md §4.5, §6.2; Addendum v2.1 §3).

A repository is a target surface like any other, so it gets the same
treatment as a URL: **nothing is scanned until the scope is resolved, and an
absent or ambiguous scope refuses the run rather than defaulting to
everything.** The failure mode this prevents is a scanner pointed at a
checkout that happens to contain a second, unauthorized project — or a
developer's `~/.aws` — because nobody said where the boundary was.

Three things are enforced here, and each maps to a way that can go wrong:

* **Path traversal.** Every candidate is resolved and re-checked to be
  inside the workspace root, so a symlink or a `..` in an exclude pattern
  cannot reach outside it.
* **Exclusions before inclusions.** `excluded_paths` wins over
  `allowed_paths`, mirroring the scope engine's rule that a deny always
  beats an allow.
* **A size cap.** A repository larger than the declared cap is refused
  rather than silently truncated, because a partial scan reported as a
  complete one is the dishonest outcome.
"""

import fnmatch
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_MAX_REPO_SIZE_MB = 500

# Directories that are never worth walking and would dominate both the size
# cap and the scan time. Excluding them is a performance decision, not a
# security one, so they are listed separately from the operator's own rules.
_ALWAYS_SKIPPED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".tox",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
        ".next",
    }
)


class CodeScopeError(ValueError):
    """The code scope is absent, ambiguous, or cannot be honoured."""


@dataclass(frozen=True)
class CodeScope:
    """Which files inside a checkout an assessment may read."""

    allowed_paths: tuple[str, ...] = ()
    excluded_paths: tuple[str, ...] = ()
    max_repo_size_mb: int = DEFAULT_MAX_REPO_SIZE_MB
    # Hosts a repository may be cloned from. Empty permits nothing: an
    # operator-supplied `repo_ref` is untrusted input, and an unstated host
    # list is not a permissive one (see `checkout.check_host_allowed`).
    allowed_repo_hosts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.allowed_paths:
            # Fail closed. An empty allowlist could mean "everything" or
            # "nothing"; the safe reading of an unstated boundary is that
            # there is not one yet.
            raise CodeScopeError(
                "code_scope.allowed_paths is empty: declare which paths may be "
                "scanned. An unstated scope is not a permissive one."
            )
        if self.max_repo_size_mb <= 0:
            raise CodeScopeError("code_scope.max_repo_size_mb must be positive")


@dataclass(frozen=True)
class Workspace:
    """A resolved checkout plus the scope that bounds what may be read."""

    root: Path
    scope: CodeScope
    languages: tuple[str, ...] = ()
    build_manifest_paths: tuple[str, ...] = ()
    files: tuple[Path, ...] = field(default=())

    @property
    def relative_files(self) -> tuple[str, ...]:
        return tuple(str(path.relative_to(self.root)) for path in self.files)

    def contains(self, path: Path) -> bool:
        """Is this path inside the workspace *after* symlinks are resolved?"""
        try:
            resolved = path.resolve()
        except OSError:
            return False
        return resolved == self.root or self.root in resolved.parents

    def manifests(self) -> list[Path]:
        """Declared build manifests that exist and are in scope."""
        found: list[Path] = []
        for name in self.build_manifest_paths:
            candidate = (self.root / name).resolve()
            if self.contains(candidate) and candidate.is_file() and candidate in self.files:
                found.append(candidate)
        return found


def _matches(relative: str, patterns: tuple[str, ...]) -> bool:
    for pattern in patterns:
        if fnmatch.fnmatch(relative, pattern):
            return True
        # `src/**` should match `src/a/b.py`, which fnmatch alone does not do
        # because it treats `**` as a single `*`.
        prefix = pattern.rstrip("*").rstrip("/")
        if prefix and (relative == prefix or relative.startswith(prefix + "/")):
            return True
    return False


def _walk(root: Path) -> Iterator[Path]:
    for path in sorted(root.rglob("*")):
        if any(part in _ALWAYS_SKIPPED_DIRS for part in path.parts):
            continue
        if path.is_symlink() or not path.is_file():
            continue
        yield path


def resolve_workspace(
    root: Path,
    scope: CodeScope,
    *,
    languages: tuple[str, ...] = (),
    build_manifest_paths: tuple[str, ...] = (),
) -> Workspace:
    """Enumerate the in-scope files under `root`.

    Raises `CodeScopeError` if the checkout is missing or exceeds the
    declared size cap. Returning a truncated file list instead would produce
    a scan that looks complete and is not.
    """
    root = root.resolve()
    if not root.is_dir():
        raise CodeScopeError(f"code checkout {root} is not a directory")

    selected: list[Path] = []
    total_bytes = 0
    cap_bytes = scope.max_repo_size_mb * 1024 * 1024

    for path in _walk(root):
        if root not in path.parents:
            continue
        relative = str(path.relative_to(root))

        # Exclusions first: a deny beats an allow, as in the scope engine.
        if _matches(relative, scope.excluded_paths):
            continue
        if not _matches(relative, scope.allowed_paths):
            continue

        try:
            total_bytes += path.stat().st_size
        except OSError:
            continue
        if total_bytes > cap_bytes:
            raise CodeScopeError(
                f"in-scope content exceeds code_scope.max_repo_size_mb "
                f"({scope.max_repo_size_mb} MB); narrow the scope or raise the cap "
                "rather than scanning part of it and reporting a complete result"
            )
        selected.append(path)

    return Workspace(
        root=root,
        scope=scope,
        languages=languages,
        build_manifest_paths=build_manifest_paths,
        files=tuple(selected),
    )
