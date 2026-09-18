class AuthorizationRequiredError(Exception):
    """No authorization record was resolved for the target. Run refused."""


class RoEValidationError(Exception):
    """The Rules of Engagement document failed schema validation. Run refused."""
