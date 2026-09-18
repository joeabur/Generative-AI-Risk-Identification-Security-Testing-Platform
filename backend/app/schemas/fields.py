from typing import Annotated

import email_validator
from pydantic import BeforeValidator

from app.core.config import get_settings


def _validate_email(value: str) -> str:
    """Email syntax validation with reserved/example domains allowed outside production.

    RFC 2606 reserves `example.com`/`example.org`/`example.test`/`.invalid`/
    `.localhost` precisely so they can be used in documentation, tests, and
    demo data without risk of delivering to a real mailbox — but
    `email_validator` rejects them by default. Synthetic seed data and tests
    throughout this project intentionally use those domains
    (docs/BUILD_SPEC.md §19, §2.4), so `test_environment` tracks whether this
    is a production deployment rather than being hardcoded either way.
    """
    settings = get_settings()
    validated = email_validator.validate_email(
        value,
        check_deliverability=False,
        test_environment=settings.environment != "production",
    )
    return validated.normalized


Email = Annotated[str, BeforeValidator(_validate_email)]
