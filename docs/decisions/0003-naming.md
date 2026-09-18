# ADR 0003: Product name is "Aegis AI Security" (`aegis-ai-security`); trademark/namespace check still owed

## Status

Accepted, with a known follow-up

## Context

The v2.0 spec explicitly warned that `aegis` is heavily used already (Aegis Authenticator, several existing
security products, PyPI squatting) and asked for a PyPI/npm/GitHub/trademark check before committing to a
name, suggesting the placeholder be kept as a single constant so a rename stays a one-commit change. The
Master Build Prompt names the product outright: "Aegis AI Security", repository `aegis-ai-security`.

## Decision

Adopt "Aegis AI Security" as the product name and `aegis-ai-security` as the repository name, as specified
by the Master Build Prompt. The CLI binary is named `aegis-ai` (not bare `aegis`) specifically to reduce
collision risk with the existing `aegis` PyPI/npm namespace noted in the v2.0 spec.

The product name and package/binary names are kept as single named constants (`PRODUCT_NAME` in shared
config, the `pyproject.toml` package name, the CLI entry-point name, the frontend's site title) rather than
scattered string literals, so that if the still-owed PyPI/npm/GitHub/trademark search turns up a genuine
conflict, the rename is a one-commit change as the v2.0 spec required.

## Follow-up (not blocking Phase 1)

Before a public v0.1.0 release, run and record the actual namespace checks:
- PyPI: package name availability for `aegis-ai` / `aegis-ai-security`
- npm: package name availability (frontend tooling, any published CLI wrapper)
- GitHub: organization/repo name collision check
- A basic trademark search for "Aegis AI Security" in the security-tooling space

Record the outcome here or in a follow-up ADR before tagging the first public release.
