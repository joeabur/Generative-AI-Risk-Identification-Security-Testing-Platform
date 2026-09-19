"""Response shapes for the evidence endpoints (docs/BUILD_SPEC.md §13).

The manifest is deliberately separate from bundle contents: listing what
evidence exists, and who wrote it when, does not require handing over the
exchange itself.
"""

from pydantic import BaseModel, ConfigDict


class EvidenceManifestEntryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    sequence: int
    digest: str
    previous: str
    chain: str
    probe_id: str
    created_at: str


class EvidenceVerificationRead(BaseModel):
    ok: bool
    entries: int
    problems: list[str]
