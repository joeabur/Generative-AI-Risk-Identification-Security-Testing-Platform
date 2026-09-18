"""A deliberately small JSONPath subset for pulling a value out of a target's
JSON response (docs/BUILD_SPEC.md §8: `response_path: $.message.content`).

Supported: `$`, `.key`, `['key']`, `["key"]`, `[0]` — e.g.
`$.choices[0].message.content`. Filters, wildcards, slices and recursive
descent are **not** supported; a path using them raises `JsonPathError` at
config time rather than silently matching nothing at scan time.

This is a full third-party JSONPath library's job in principle, but the
supported subset covers every response shape the shipped adapters need, and
a ~60-line parser with explicit failure modes is easier to audit than a
dependency for a security tool's extraction layer.
"""

from typing import Any


class JsonPathError(ValueError):
    """The path itself is malformed — an operator configuration error, not a
    missing value in a response."""


def _tokenize(path: str) -> list[str | int]:
    if not path.startswith("$"):
        raise JsonPathError(f"path must start with '$': {path!r}")

    tokens: list[str | int] = []
    index = 1
    while index < len(path):
        char = path[index]
        if char == ".":
            end = index + 1
            while end < len(path) and path[end] not in ".[":
                end += 1
            key = path[index + 1 : end]
            if not key:
                raise JsonPathError(f"empty key in path {path!r}")
            if key == "*" or key.startswith("."):
                raise JsonPathError(f"unsupported wildcard/recursive syntax in path {path!r}")
            tokens.append(key)
            index = end
        elif char == "[":
            end = path.find("]", index)
            if end == -1:
                raise JsonPathError(f"unclosed '[' in path {path!r}")
            inner = path[index + 1 : end].strip()
            if len(inner) >= 2 and inner[0] == inner[-1] and inner[0] in {"'", '"'}:
                tokens.append(inner[1:-1])
            else:
                try:
                    tokens.append(int(inner))
                except ValueError as exc:
                    raise JsonPathError(
                        f"unsupported bracket expression {inner!r} in path {path!r}"
                    ) from exc
            index = end + 1
        else:
            raise JsonPathError(f"unexpected character {char!r} at position {index} in {path!r}")
    return tokens


def extract(data: Any, path: str) -> Any | None:
    """Return the value at `path`, or None if any step is missing.

    A malformed *path* raises; a path that simply does not match the given
    *data* returns None, because that is a legitimate runtime outcome (the
    target answered in a shape the operator did not expect) rather than a
    configuration bug.
    """
    tokens = _tokenize(path)
    current: Any = data
    for token in tokens:
        if isinstance(token, int):
            if not isinstance(current, list) or token >= len(current) or token < -len(current):
                return None
            current = current[token]
        else:
            if not isinstance(current, dict) or token not in current:
                return None
            current = current[token]
    return current


def validate_path(path: str) -> None:
    """Raise `JsonPathError` if the path is unusable. Called when an adapter
    is configured so a typo surfaces immediately instead of as a silent
    "the probe found nothing" during a run."""
    _tokenize(path)
