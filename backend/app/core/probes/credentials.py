"""Synthetic test accounts for authorization probes (docs/BUILD_SPEC.md §10).

Two rules shape everything here.

**A credential is never stored.** The platform stores the *name of an
environment variable*, and the worker resolves it at run time. Nothing in
the database, in an uploaded file, or in a report ever holds the secret, so
losing any of those does not lose the credential. That is §2's
"credentials are reference-only", enforced by the type: `SyntheticAccount`
has no field that could hold one.

**A secret never reaches evidence.** `CredentialSet` hands back headers and
nothing else, and its repr is deliberately uninformative, so a token cannot
be written into a finding by a probe that logs the wrong variable.
"""

import os
from collections.abc import Mapping
from dataclasses import dataclass, field


class CredentialUnavailableError(RuntimeError):
    """A declared account's environment variable is not set in the worker."""


@dataclass(frozen=True)
class SyntheticAccount:
    """An authorized test account, described without its secret.

    `owned_object_ids` are real identifiers of records this account owns, so
    a BOLA probe can ask about a *real* object without ever touching a
    stranger's data — the §10 requirement that makes this test safe to run.
    """

    label: str
    credential_env_var: str
    header_name: str = "Authorization"
    value_template: str = "Bearer {credential}"
    owned_object_ids: tuple[str, ...] = ()
    is_privileged: bool = False

    def header_for(self, credential: str) -> dict[str, str]:
        return {self.header_name: self.value_template.format(credential=credential)}


class CredentialSet:
    """Resolved secrets for a run, exposed only as request headers."""

    def __init__(self, secrets: Mapping[str, str]) -> None:
        self._secrets = dict(secrets)

    @classmethod
    def from_environment(
        cls, accounts: "tuple[SyntheticAccount, ...]", environ: Mapping[str, str] | None = None
    ) -> "CredentialSet":
        """Resolve each account's variable, skipping the ones that are unset.

        An unset variable is not an error: the probes that need an account
        decline to run and say so, which is a far better outcome than a run
        that fails outright because one optional account was not configured.
        """
        source = os.environ if environ is None else environ
        resolved = {
            account.label: source[account.credential_env_var]
            for account in accounts
            if source.get(account.credential_env_var)
        }
        return cls(resolved)

    def has(self, account: SyntheticAccount) -> bool:
        return account.label in self._secrets

    def headers_for(self, account: SyntheticAccount) -> dict[str, str]:
        if account.label not in self._secrets:
            raise CredentialUnavailableError(
                f"no credential resolved for account {account.label!r} "
                f"(expected environment variable {account.credential_env_var})"
            )
        return account.header_for(self._secrets[account.label])

    def __repr__(self) -> str:  # pragma: no cover - defensive, never asserted on
        return f"<CredentialSet accounts={sorted(self._secrets)!r}>"


@dataclass(frozen=True)
class AuthorizationTestPlan:
    """The accounts available to the authorization probes."""

    accounts: tuple[SyntheticAccount, ...] = ()
    credentials: CredentialSet = field(default_factory=lambda: CredentialSet({}))

    def usable(self) -> list[SyntheticAccount]:
        return [account for account in self.accounts if self.credentials.has(account)]
