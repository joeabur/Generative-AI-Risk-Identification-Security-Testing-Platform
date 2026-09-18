import re
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator

# An environment variable name, nothing else. The pattern is what keeps this
# field from being used to smuggle a credential in as its own "name".
_ENV_VAR = re.compile(r"^[A-Z][A-Z0-9_]{0,199}$")


class SyntheticAccountUpsert(BaseModel):
    label: str = Field(min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=500)
    credential_env_var: str = Field(min_length=1, max_length=200)
    header_name: str = Field(default="Authorization", min_length=1, max_length=100)
    value_template: str = Field(default="Bearer {credential}", min_length=1, max_length=200)
    owned_object_ids: list[str] = Field(default_factory=list, max_length=50)
    is_privileged: bool = False

    @field_validator("credential_env_var")
    @classmethod
    def _looks_like_an_env_var_name(cls, value: str) -> str:
        if not _ENV_VAR.match(value):
            raise ValueError(
                "credential_env_var must be the NAME of an environment variable "
                "(A-Z, digits and underscores), not a credential value"
            )
        return value

    @field_validator("value_template")
    @classmethod
    def _references_the_credential(cls, value: str) -> str:
        if "{credential}" not in value:
            raise ValueError("value_template must contain the {credential} placeholder")
        return value

    @field_validator("owned_object_ids")
    @classmethod
    def _bounded_ids(cls, value: list[str]) -> list[str]:
        for object_id in value:
            if not object_id or len(object_id) > 200:
                raise ValueError("each owned object id must be 1-200 characters")
        return value


class SyntheticAccountRead(BaseModel):
    """Note the absence of any credential field — there is nothing to hide,
    because the platform never has the secret to begin with."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target_id: uuid.UUID
    label: str
    description: str | None
    credential_env_var: str
    header_name: str
    value_template: str
    owned_object_ids: list[str]
    is_privileged: bool
