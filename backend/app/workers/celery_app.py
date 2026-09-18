from celery import Celery

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "aegis_ai_security",
    broker=settings.redis_url,
    backend=settings.redis_url,
    # Without this the worker starts happily but never registers
    # `aegis.run_assessment`, and every queued run is discarded as an
    # "unregistered task" while the API reports it as queued.
    include=["app.workers.tasks"],
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
    """Liveness probe for the worker/broker wiring. Makes no outbound
    request of its own; assessment work lives in `app.workers.tasks`."""
    return {"status": "ok"}
