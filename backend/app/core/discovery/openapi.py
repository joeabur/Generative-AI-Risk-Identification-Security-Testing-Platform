"""OpenAPI 3.x parsing and attack-surface extraction (docs/BUILD_SPEC.md §26
Phase 3: "handles malformed specs without crashing").

An uploaded spec is untrusted input supplied by whoever is operating the
platform about a system they may not control, so this parser treats it as
hostile rather than merely imperfect:

- **YAML is parsed with `safe_load` only.** `yaml.load` would allow arbitrary
  object construction from a document we are about to accept over HTTP.
- **Remote `$ref`s are refused, never fetched.** A spec containing
  `$ref: "https://evil.test/x.yaml"` is an SSRF primitive aimed squarely at
  the machine running the scanner; resolving it "helpfully" would be a
  vulnerability in a tool whose entire premise is not making requests it was
  not authorized to make.
- **Local `$ref` resolution is cycle-safe and depth-capped**, because a
  self-referential schema is a trivial way to hang the parser.
- **Document size and operation count are capped**, so a spec cannot exhaust
  memory or produce an unbounded surface.

Anything it cannot parse raises `OpenApiParseError` with a message an
operator can act on; nothing here raises a bare library exception at the
caller.
"""

import json
from dataclasses import dataclass, field
from typing import Any

import yaml

MAX_DOCUMENT_BYTES = 5 * 1024 * 1024
MAX_OPERATIONS = 2000
MAX_REF_DEPTH = 8

_HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")


class OpenApiParseError(ValueError):
    """The document is not a usable OpenAPI 3.x spec."""


@dataclass(frozen=True)
class DiscoveredParameter:
    name: str
    location: str  # "query" | "header" | "path" | "cookie"
    required: bool = False
    schema_type: str | None = None


@dataclass(frozen=True)
class DiscoveredOperation:
    method: str
    path: str
    operation_id: str | None = None
    summary: str | None = None
    parameters: tuple[DiscoveredParameter, ...] = ()
    request_body_content_types: tuple[str, ...] = ()
    security_schemes: tuple[str, ...] = ()
    requires_auth: bool = False


@dataclass(frozen=True)
class DiscoveredSurface:
    title: str | None
    version: str | None
    openapi_version: str
    servers: tuple[str, ...]
    operations: tuple[DiscoveredOperation, ...] = field(default=())


def load_document(raw: str | bytes) -> dict[str, Any]:
    """Parse a raw JSON or YAML document into a mapping, with a size cap.

    JSON is attempted first because every JSON document is also valid YAML
    but the JSON parser gives better error messages and is considerably
    faster on large specs.
    """
    if isinstance(raw, bytes):
        if len(raw) > MAX_DOCUMENT_BYTES:
            raise OpenApiParseError(f"document is larger than the {MAX_DOCUMENT_BYTES} byte limit")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise OpenApiParseError("document is not valid UTF-8") from exc
    else:
        text = raw
        if len(text.encode("utf-8")) > MAX_DOCUMENT_BYTES:
            raise OpenApiParseError(f"document is larger than the {MAX_DOCUMENT_BYTES} byte limit")

    if not text.strip():
        raise OpenApiParseError("document is empty")

    try:
        parsed = json.loads(text)
    except ValueError:
        try:
            parsed = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise OpenApiParseError(
                f"document is neither valid JSON nor valid YAML: {exc}"
            ) from exc

    if not isinstance(parsed, dict):
        raise OpenApiParseError("document root must be a mapping")
    return parsed


def parse_surface(document: dict[str, Any]) -> DiscoveredSurface:
    """Extract the testable surface from an already-loaded OpenAPI document."""
    openapi_version = document.get("openapi")
    if openapi_version is None:
        if "swagger" in document:
            raise OpenApiParseError(
                "Swagger 2.0 documents are not supported; convert to OpenAPI 3.x first"
            )
        raise OpenApiParseError("missing 'openapi' version field")
    if not isinstance(openapi_version, str) or not openapi_version.startswith("3."):
        raise OpenApiParseError(f"unsupported OpenAPI version {openapi_version!r}; 3.x required")

    info = document.get("info")
    title = info.get("title") if isinstance(info, dict) else None
    version = info.get("version") if isinstance(info, dict) else None

    servers: list[str] = []
    raw_servers = document.get("servers")
    if isinstance(raw_servers, list):
        for server in raw_servers:
            if isinstance(server, dict) and isinstance(server.get("url"), str):
                servers.append(server["url"])

    paths = document.get("paths")
    if paths is None:
        raise OpenApiParseError("missing 'paths' object")
    if not isinstance(paths, dict):
        raise OpenApiParseError("'paths' must be a mapping")

    global_security = _security_scheme_names(document.get("security"))
    operations: list[DiscoveredOperation] = []

    for path, path_item in paths.items():
        if not isinstance(path, str) or not isinstance(path_item, dict):
            # A malformed entry is skipped rather than aborting the whole
            # upload: a partially usable surface still beats none, and the
            # operator can see what was and was not discovered.
            continue

        path_item = _resolve_refs(path_item, document)
        shared_parameters = _parse_parameters(path_item.get("parameters"), document)

        for method in _HTTP_METHODS:
            operation = path_item.get(method)
            if not isinstance(operation, dict):
                continue
            operation = _resolve_refs(operation, document)

            if len(operations) >= MAX_OPERATIONS:
                raise OpenApiParseError(f"document declares more than {MAX_OPERATIONS} operations")

            own_security = operation.get("security")
            security_names = (
                _security_scheme_names(own_security)
                if own_security is not None
                else global_security
            )
            # An explicit empty `security: []` on an operation means "this one
            # is public" and overrides the document-level requirement.
            requires_auth = bool(security_names)

            operations.append(
                DiscoveredOperation(
                    method=method.upper(),
                    path=path,
                    operation_id=_optional_str(operation.get("operationId")),
                    summary=_optional_str(operation.get("summary")),
                    parameters=shared_parameters
                    + _parse_parameters(operation.get("parameters"), document),
                    request_body_content_types=_request_body_content_types(
                        operation.get("requestBody"), document
                    ),
                    security_schemes=tuple(security_names),
                    requires_auth=requires_auth,
                )
            )

    return DiscoveredSurface(
        title=_optional_str(title),
        version=_optional_str(version),
        openapi_version=openapi_version,
        servers=tuple(servers),
        operations=tuple(operations),
    )


def parse(raw: str | bytes) -> DiscoveredSurface:
    return parse_surface(load_document(raw))


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _security_scheme_names(security: Any) -> list[str]:
    if not isinstance(security, list):
        return []
    names: list[str] = []
    for requirement in security:
        if isinstance(requirement, dict):
            names.extend(str(name) for name in requirement)
    return names


def _parse_parameters(raw: Any, document: dict[str, Any]) -> tuple[DiscoveredParameter, ...]:
    if not isinstance(raw, list):
        return ()
    parameters: list[DiscoveredParameter] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        resolved = _resolve_refs(entry, document)
        name = resolved.get("name")
        location = resolved.get("in")
        if not isinstance(name, str) or not isinstance(location, str):
            continue
        schema = resolved.get("schema")
        schema_type = schema.get("type") if isinstance(schema, dict) else None
        parameters.append(
            DiscoveredParameter(
                name=name,
                location=location,
                required=bool(resolved.get("required", False)),
                schema_type=_optional_str(schema_type),
            )
        )
    return tuple(parameters)


def _request_body_content_types(raw: Any, document: dict[str, Any]) -> tuple[str, ...]:
    if not isinstance(raw, dict):
        return ()
    resolved = _resolve_refs(raw, document)
    content = resolved.get("content")
    if not isinstance(content, dict):
        return ()
    return tuple(str(media_type) for media_type in content)


def _resolve_refs(
    node: dict[str, Any],
    document: dict[str, Any],
    *,
    depth: int = 0,
    seen: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Resolve a single level of local `$ref` indirection.

    Only the node itself is resolved (not every nested schema): the surface
    model here needs parameter and body *shapes*, not fully inlined schemas,
    and refusing to walk the entire schema graph is what keeps a hostile
    document from turning into an exponential expansion.
    """
    ref = node.get("$ref")
    if not isinstance(ref, str):
        return node

    if not ref.startswith("#/"):
        raise OpenApiParseError(
            f"refusing to resolve non-local $ref {ref!r}: remote references are not fetched"
        )
    if depth >= MAX_REF_DEPTH:
        raise OpenApiParseError(f"$ref nesting deeper than {MAX_REF_DEPTH} levels")
    if ref in seen:
        raise OpenApiParseError(f"circular $ref detected at {ref!r}")

    target: Any = document
    for segment in ref[2:].split("/"):
        segment = segment.replace("~1", "/").replace("~0", "~")
        if not isinstance(target, dict) or segment not in target:
            raise OpenApiParseError(f"$ref {ref!r} does not resolve")
        target = target[segment]

    if not isinstance(target, dict):
        raise OpenApiParseError(f"$ref {ref!r} does not point at a mapping")

    merged = {key: value for key, value in node.items() if key != "$ref"}
    resolved = _resolve_refs(target, document, depth=depth + 1, seen=seen | {ref})
    return {**resolved, **merged}
