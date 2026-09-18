import os
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

os.environ.setdefault(
    "DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost:5432/aegis_test"
)
os.environ.setdefault("ENVIRONMENT", "ci")
os.environ.setdefault("JWT_SECRET", "test-only-secret-do-not-use-elsewhere")

from app.api.v1.routers.targets import get_dns_resolver  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from app.db.session import get_db  # noqa: E402
from app.main import create_app  # noqa: E402
from tests.security.conftest import FakeDnsResolver  # noqa: E402

get_settings.cache_clear()
settings = get_settings()

test_engine = create_async_engine(settings.database_url)
TestSessionLocal = async_sessionmaker(bind=test_engine, expire_on_commit=False, class_=AsyncSession)

_TABLES = [
    "rules_of_engagement",
    "authorizations",
    "targets",
    "memberships",
    "audit_logs",
    "users",
    "organizations",
]


@pytest_asyncio.fixture(autouse=True)
async def _clean_database() -> AsyncGenerator[None, None]:
    yield
    async with test_engine.begin() as conn:
        await conn.execute(text(f"TRUNCATE TABLE {', '.join(_TABLES)} RESTART IDENTITY CASCADE"))


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    async with TestSessionLocal() as session:
        yield session


@pytest_asyncio.fixture
async def client() -> AsyncGenerator[AsyncClient, None]:
    app = create_app()

    async def _override_get_db() -> AsyncGenerator[AsyncSession, None]:
        async with TestSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_dns_resolver] = lambda: FakeDnsResolver(
        {
            "ai.example.test": ["203.0.113.5"],
            "sub.ai.example.test": ["203.0.113.6"],
            "evil.test": ["203.0.113.99"],
        }
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest.fixture
def strong_password() -> str:
    return "Correct-Horse-Battery-Staple-9"
