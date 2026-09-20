"""Code-host connection shapes (docs/BUILD_SPEC.md §27).

`VcsConnectionRead` carries `token_env_var` and never a token, because there is
no endpoint that returns one — the value is not in the database to return.
"""

import re
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.vcs.contract import VcsProvider
from app.core.vcs.policy import valid_env_var_name

#: GitHub's own rule for owner and repository names, applied here so a slug
#: cannot smuggle a path segment (`owner/repo/../../other`) into an API URL.
_SEGMENT = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_SHA = re.compile(r"^[0-9a-fA-F]{7,64}$")


class VcsConnectionCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    provider: VcsProvider
    token_env_var: str = Field(max_length=128)
    #: GitHub Enterprise only. github.com's API host is pinned in code.
    api_host: str | None = Field(default=None, max_length=255)
    enabled: bool = True

    @model_validator(mode="after")
    def check_fields(self) -> "VcsConnectionCreate":
        if not valid_env_var_name(self.token_env_var):
            raise ValueError(
                f"{self.token_env_var!r} is not a valid environment variable name; a "
                "connection references its token by variable name, not by value"
            )
        if self.provider is VcsProvider.GITHUB_ENTERPRISE and not self.api_host:
            raise ValueError("api_host is required for a GitHub Enterprise connection")
        if self.provider is VcsProvider.GITHUB and self.api_host:
            raise ValueError(
                "a github connection always reaches api.github.com; use "
                "github_enterprise for a self-hosted install"
            )
        return self


class VcsConnectionUpdate(BaseModel):
    """Only `enabled`.

    Changing the token variable or the host is creating a different connection:
    doing it in place would leave the post history attached to a repository it
    never wrote to.
    """

    enabled: bool


class VcsConnectionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    provider: str
    api_host: str | None
    token_env_var: str
    enabled: bool
    created_at: datetime


class PublishRequest(BaseModel):
    repo_owner: str = Field(max_length=100)
    repo_name: str = Field(max_length=100)
    pull_number: int = Field(ge=1)
    head_sha: str = Field(max_length=64)
    #: The run whose findings to publish. Required: publishing "the latest
    #: findings" would make what a pull request says depend on when it was
    #: asked, which is not something a reviewer can reason about.
    run_id: uuid.UUID

    @model_validator(mode="after")
    def check_refs(self) -> "PublishRequest":
        for label, value in (("repo_owner", self.repo_owner), ("repo_name", self.repo_name)):
            if not _SEGMENT.match(value):
                raise ValueError(f"{label} is not a valid GitHub name segment")
        if not _SHA.match(self.head_sha):
            raise ValueError("head_sha is not a commit SHA")
        return self


class PullRequestPostRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    connection_id: uuid.UUID
    assessment_run_id: uuid.UUID | None
    repo_slug: str
    pull_number: int
    head_sha: str
    conclusion: str
    check_run_url: str | None
    annotations_posted: int
    annotations_dropped: int
    findings_total: int
    posted_at: datetime | None
    detail: str | None
    created_at: datetime
