"""Building the AI service from configuration.

The platform is designed to work with no provider configured, so this
returns a service with no provider rather than raising: callers get a
service whose `configured` is `False`, and every method on it refuses
clearly instead of the application failing to start.
"""

from app.core.assistant.autonomy import AutonomyMode
from app.core.assistant.openai_compatible import OpenAICompatibleProvider
from app.core.assistant.provider import AIProvider, ProviderConfig
from app.core.assistant.service import AIService
from app.core.config import Settings


def provider_config(settings: Settings) -> ProviderConfig | None:
    if not (settings.ai_provider and settings.ai_endpoint and settings.ai_model):
        return None
    return ProviderConfig(
        provider=settings.ai_provider,
        endpoint=settings.ai_endpoint,
        model=settings.ai_model,
        api_key_env_var=settings.ai_api_key_env_var,
    )


def build_ai_service(settings: Settings, provider: AIProvider | None = None) -> AIService:
    """The configured service, or an unconfigured one that refuses cleanly."""
    try:
        mode = AutonomyMode.parse(settings.ai_autonomy_mode)
    except ValueError:
        # An unreadable mode is treated as OFF rather than as the default:
        # a typo in configuration must not silently grant more autonomy than
        # the operator intended.
        mode = AutonomyMode.OFF

    if provider is not None:
        return AIService(provider, mode=mode)

    config = provider_config(settings)
    if config is None:
        return AIService(None, mode=mode)
    return AIService(OpenAICompatibleProvider(config), mode=mode)
