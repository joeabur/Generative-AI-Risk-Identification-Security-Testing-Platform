from celery import Celery

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "aegis_ai_security",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
)


@celery_app.task(name="aegis.health_check")
def health_check() -> dict[str, str]:
    """Placeholder task proving the worker/broker wiring works end to end.

    The real scan orchestration tasks (core/orchestrator/) land in Phase 4
    (docs/BUILD_SPEC.md §26) and must call into core/scope/ for every
    outbound request they make — this task deliberately makes none.
    """
    return {"status": "ok"}
