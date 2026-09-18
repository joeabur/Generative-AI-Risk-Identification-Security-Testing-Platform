"""Single source of truth for product naming.

Kept as named constants (per docs/decisions/0003-naming.md) so a rename stays
a one-commit change if the trademark/namespace check turns up a conflict.
"""

PRODUCT_NAME = "Aegis AI Security"
CLI_BINARY_NAME = "aegis-ai"
API_VERSION_PREFIX = "/api/v1"
