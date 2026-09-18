"""Two OpenAPI documents describing the same API, one badly and one well.

Several probes read the specification rather than the wire — mass
assignment, key material in URLs — so the seeded flaws have to exist in the
document, not only in the handlers. These two specs differ exactly where
that matters.
"""

from typing import Any

_ORDER_PARAM = {
    "name": "order_id",
    "in": "path",
    "required": True,
    "schema": {"type": "string"},
}

_BEARER = {"bearerAuth": []}


def vulnerable_spec() -> dict[str, Any]:
    return {
        "openapi": "3.0.3",
        "info": {"title": "Vulnerable Lab API", "version": "1.0"},
        "security": [_BEARER],
        "paths": {
            "/api/search": {
                "get": {
                    "operationId": "search",
                    "security": [],
                    "parameters": [
                        {"name": "q", "in": "query", "schema": {"type": "string"}},
                        {"name": "limit", "in": "query", "schema": {"type": "integer"}},
                        # Seeded: key material in the URL (API2 / CWE-598).
                        {"name": "api_key", "in": "query", "schema": {"type": "string"}},
                    ],
                    "responses": {"200": {"description": "ok"}},
                }
            },
            "/api/orders/{order_id}": {
                "get": {
                    "operationId": "getOrder",
                    "parameters": [_ORDER_PARAM],
                    "responses": {"200": {"description": "ok"}},
                }
            },
            "/api/admin/users": {
                "get": {
                    "operationId": "adminListUsers",
                    "responses": {"200": {"description": "ok"}},
                }
            },
            "/api/users": {
                "post": {
                    "operationId": "createUser",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["email"],
                                    "properties": {
                                        # Seeded: a read schema reused for writes.
                                        "id": {"type": "string", "readOnly": True},
                                        "email": {"type": "string"},
                                        # Seeded: privileged fields are bindable (API3).
                                        "role": {"type": "string"},
                                        "is_admin": {"type": "boolean"},
                                    },
                                }
                            }
                        },
                    },
                    "responses": {"201": {"description": "created"}},
                }
            },
            "/graphql": {
                "post": {
                    "operationId": "graphql",
                    "security": [],
                    "requestBody": {
                        "content": {"application/json": {"schema": {"type": "object"}}}
                    },
                    "responses": {"200": {"description": "ok"}},
                }
            },
        },
    }


def hardened_spec() -> dict[str, Any]:
    """The same API, described the way it should be.

    No credential in the URL, no privileged field bindable, and no readOnly
    field on a write body — so the analysis-mode probes have nothing to
    report even before a single request is sent.
    """
    return {
        "openapi": "3.0.3",
        "info": {"title": "Hardened Control API", "version": "1.0"},
        "security": [_BEARER],
        "paths": {
            "/api/search": {
                "get": {
                    "operationId": "search",
                    "security": [],
                    "parameters": [
                        {"name": "q", "in": "query", "schema": {"type": "string"}},
                        {
                            "name": "limit",
                            "in": "query",
                            "schema": {"type": "integer", "maximum": 100},
                        },
                    ],
                    "responses": {"200": {"description": "ok"}},
                }
            },
            "/api/orders/{order_id}": {
                "get": {
                    "operationId": "getOrder",
                    "parameters": [_ORDER_PARAM],
                    "responses": {"200": {"description": "ok"}},
                }
            },
            "/api/admin/users": {
                "get": {
                    "operationId": "adminListUsers",
                    "responses": {"200": {"description": "ok"}},
                }
            },
            "/api/users": {
                "post": {
                    "operationId": "createUser",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["email"],
                                    "properties": {"email": {"type": "string"}},
                                }
                            }
                        },
                    },
                    "responses": {"201": {"description": "created"}},
                }
            },
            "/graphql": {
                "post": {
                    "operationId": "graphql",
                    "security": [],
                    "requestBody": {
                        "content": {"application/json": {"schema": {"type": "object"}}}
                    },
                    "responses": {"200": {"description": "ok"}},
                }
            },
        },
    }
