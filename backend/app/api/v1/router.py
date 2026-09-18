from fastapi import APIRouter

from app.api.v1.routers import auth, health, organizations, runs, surface, targets

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(organizations.router)
api_router.include_router(targets.router)
api_router.include_router(surface.router)
api_router.include_router(runs.router)
