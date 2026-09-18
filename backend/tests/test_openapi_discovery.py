"""OpenAPI parsing, including the hostile-input cases.

An uploaded spec is untrusted input, so the "malformed specs don't crash"
acceptance criterion (docs/BUILD_SPEC.md §26 Phase 3) is treated here as a
security property, not just robustness: remote `$ref`s must never be
fetched, cycles must not hang, and oversized documents must be refused.
"""

import json

import pytest

from app.core.discovery import openapi

MINIMAL_SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "Demo AI App", "version": "1.2.3"},
    "servers": [{"url": "https://ai.example.test"}],
    "paths": {
        "/api/chat": {
            "post": {
                "operationId": "chat",
                "summary": "Send a chat message",
                "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}},
                "responses": {"200": {"description": "ok"}},
            }
        },
        "/api/orders/{order_id}": {
            "parameters": [
                {"name": "order_id", "in": "path", "required": True, "schema": {"type": "string"}}
            ],
            "get": {
                "operationId": "getOrder",
                "responses": {"200": {"description": "ok"}},
            },
        },
    },
    "security": [{"bearerAuth": []}],
}


def test_parses_operations_methods_and_paths() -> None:
    surface = openapi.parse(json.dumps(MINIMAL_SPEC))

    assert surface.title == "Demo AI App"
    assert surface.version == "1.2.3"
    assert surface.servers == ("https://ai.example.test",)

    signatures = {(operation.method, operation.path) for operation in surface.operations}
    assert signatures == {("POST", "/api/chat"), ("GET", "/api/orders/{order_id}")}


def test_path_level_parameters_are_inherited_by_operations() -> None:
    surface = openapi.parse(json.dumps(MINIMAL_SPEC))
    get_order = next(op for op in surface.operations if op.operation_id == "getOrder")

    assert [(p.name, p.location, p.required) for p in get_order.parameters] == [
        ("order_id", "path", True)
    ]


def test_global_security_marks_operations_as_requiring_auth() -> None:
    surface = openapi.parse(json.dumps(MINIMAL_SPEC))

    assert all(operation.requires_auth for operation in surface.operations)
    assert all("bearerAuth" in operation.security_schemes for operation in surface.operations)


def test_operation_level_empty_security_overrides_global_requirement() -> None:
    spec = json.loads(json.dumps(MINIMAL_SPEC))
    spec["paths"]["/api/chat"]["post"]["security"] = []

    surface = openapi.parse(json.dumps(spec))
    chat = next(op for op in surface.operations if op.path == "/api/chat")

    assert chat.requires_auth is False


def test_request_body_content_types_are_captured() -> None:
    surface = openapi.parse(json.dumps(MINIMAL_SPEC))
    chat = next(op for op in surface.operations if op.path == "/api/chat")

    assert chat.request_body_content_types == ("application/json",)


def test_yaml_documents_are_accepted() -> None:
    document = """
openapi: 3.0.0
info:
  title: YAML App
  version: "1.0"
paths:
  /api/search:
    get:
      operationId: search
      responses:
        "200":
          description: ok
"""
    surface = openapi.parse(document)

    assert surface.title == "YAML App"
    assert [(op.method, op.path) for op in surface.operations] == [("GET", "/api/search")]


def test_local_refs_are_resolved() -> None:
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Ref App", "version": "1"},
        "paths": {
            "/api/items": {
                "get": {
                    "parameters": [{"$ref": "#/components/parameters/Limit"}],
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
        "components": {
            "parameters": {"Limit": {"name": "limit", "in": "query", "schema": {"type": "integer"}}}
        },
    }

    surface = openapi.parse(json.dumps(spec))
    operation = surface.operations[0]

    assert [(p.name, p.location, p.schema_type) for p in operation.parameters] == [
        ("limit", "query", "integer")
    ]


# --- hostile / malformed input ------------------------------------------


def test_remote_ref_is_refused_and_never_fetched() -> None:
    """A spec pointing `$ref` at a remote URL is an SSRF attempt aimed at the
    scanner host; it must be rejected outright rather than resolved."""
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Evil", "version": "1"},
        "paths": {
            "/api/x": {
                "get": {
                    "parameters": [{"$ref": "https://evil.test/params.yaml#/Limit"}],
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }

    with pytest.raises(openapi.OpenApiParseError, match="remote references are not fetched"):
        openapi.parse(json.dumps(spec))


def test_circular_ref_is_detected_rather_than_hanging() -> None:
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Loop", "version": "1"},
        "paths": {"/api/x": {"get": {"$ref": "#/components/x/a"}}},
        "components": {"x": {"a": {"$ref": "#/components/x/b"}, "b": {"$ref": "#/components/x/a"}}},
    }

    with pytest.raises(openapi.OpenApiParseError):
        openapi.parse(json.dumps(spec))


def test_unresolvable_ref_reports_clearly() -> None:
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Missing", "version": "1"},
        "paths": {"/api/x": {"get": {"$ref": "#/components/nope/missing"}}},
    }

    with pytest.raises(openapi.OpenApiParseError, match="does not resolve"):
        openapi.parse(json.dumps(spec))


def test_swagger_2_is_rejected_with_an_actionable_message() -> None:
    with pytest.raises(openapi.OpenApiParseError, match="Swagger 2.0"):
        openapi.parse(json.dumps({"swagger": "2.0", "info": {}, "paths": {}}))


def test_unsupported_openapi_version_is_rejected() -> None:
    with pytest.raises(openapi.OpenApiParseError, match="3.x required"):
        openapi.parse(json.dumps({"openapi": "4.0.0", "paths": {}}))


def test_missing_paths_is_rejected() -> None:
    with pytest.raises(openapi.OpenApiParseError, match="paths"):
        openapi.parse(json.dumps({"openapi": "3.0.0", "info": {}}))


def test_empty_document_is_rejected() -> None:
    with pytest.raises(openapi.OpenApiParseError, match="empty"):
        openapi.parse("   ")


def test_non_mapping_root_is_rejected() -> None:
    with pytest.raises(openapi.OpenApiParseError, match="mapping"):
        openapi.parse(json.dumps(["not", "a", "spec"]))


def test_garbage_input_is_rejected_without_raising_a_library_error() -> None:
    with pytest.raises(openapi.OpenApiParseError):
        openapi.parse("{[ this is not: valid json or yaml ][")


def test_oversized_document_is_refused() -> None:
    oversized = b"x" * (openapi.MAX_DOCUMENT_BYTES + 1)

    with pytest.raises(openapi.OpenApiParseError, match="larger than"):
        openapi.parse(oversized)


def test_malformed_path_entries_are_skipped_not_fatal() -> None:
    """A partially usable surface beats refusing the whole upload, as long as
    what was discovered is exactly what the operator can see."""
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Mixed", "version": "1"},
        "paths": {
            "/api/good": {"get": {"responses": {"200": {"description": "ok"}}}},
            "/api/bad": "this should be a mapping",
            "/api/also-bad": {"get": "not a mapping either"},
        },
    }

    surface = openapi.parse(json.dumps(spec))

    assert [(op.method, op.path) for op in surface.operations] == [("GET", "/api/good")]


def test_yaml_is_parsed_safely_without_object_construction() -> None:
    """`yaml.safe_load` must reject python object tags outright — a spec that
    can instantiate objects on upload is remote code execution."""
    document = "!!python/object/apply:os.system ['echo pwned']\n"

    with pytest.raises(openapi.OpenApiParseError):
        openapi.parse(document)
