import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.models.surface_endpoint import SurfaceSource


class ApiSpecRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target_id: uuid.UUID
    original_filename: str
    openapi_version: str
    title: str | None
    api_version: str | None


class SurfaceEndpointRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target_id: uuid.UUID
    method: str
    path: str
    operation_id: str | None
    summary: str | None
    parameters: list[dict[str, Any]]
    request_body_content_types: list[str]
    security_schemes: list[str]
    requires_auth: bool
    enabled: bool
    source: SurfaceSource


class SurfaceImportResult(BaseModel):
    spec: ApiSpecRead
    endpoints_discovered: int
    endpoints: list[SurfaceEndpointRead]


class SurfaceEndpointUpdate(BaseModel):
    enabled: bool
