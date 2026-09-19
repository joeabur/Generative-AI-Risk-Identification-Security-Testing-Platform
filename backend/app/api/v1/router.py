from fastapi import APIRouter

from app.api.v1.routers import (
    assistant,
    auth,
    findings,
    health,
    organizations,
    remediation,
    reports,
    runs,
    surface,
    targets,
)

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(organizations.router)
api_router.include_router(targets.router)
api_router.include_router(surface.router)
api_router.include_router(runs.router)
api_router.include_router(reports.router)
api_router.include_router(findings.router)
api_router.include_router(remediation.router)
api_router.include_router(assistant.router)
