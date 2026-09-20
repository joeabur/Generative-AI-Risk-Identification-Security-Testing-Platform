import os
import pathlib
import tempfile
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
# One evidence root for the whole session, outside the repository. The worker
# and the download endpoint both read it from settings, so they agree without
# a dependency override — which is the point: the test exercises the real
# path from "a probe observed this" to "a member downloaded it".
os.environ.setdefault(
    "EVIDENCE_ROOT", str(pathlib.Path(tempfile.gettempdir()) / "aegis-test-evidence")
)
# The demo lab's static tokens, supplied the way a real engagement supplies
# credentials: by environment-variable name. They authenticate nothing outside
# the lab and are printed in demo-target/README.md.
os.environ.setdefault("AEGIS_LAB_ACME_TOKEN", "lab-token-acme-user")
os.environ.setdefault("AEGIS_LAB_GLOBEX_TOKEN", "lab-token-globex-user")

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
    "ai_drafts",
    "pull_request_posts",
    "vcs_connections",
    "notification_deliveries",
    "notification_channels",
    "api_keys",
    "retest_results",
    "remediation_tasks",
    "findings",
    "scan_results",
    "run_events",
    "assessment_runs",
    "api_specs",
    "synthetic_accounts",
    "surface_endpoints",
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
    """Start every test from an empty database.

    Cleaning **before** the test, not after, and that ordering is the whole
    point. `TRUNCATE` takes an ACCESS EXCLUSIVE lock, so it waits for any
    session an earlier test left open. Run as teardown, that wait can outlast
    the teardown itself and land in the middle of the *next* test — which then
    watches its own freshly-registered user disappear and fails with a
    confusing 401 several calls later.

    That is not hypothetical: it is what made five tests fail in a full run
    under `--cov` (which is how CI runs) while every one of them passed alone
    and passed in a full run without coverage. Coverage slows execution by
    about a quarter, which was enough to widen the window.

    Cleaning at setup gives the same guarantee — no test sees another's rows —
    and cannot corrupt a running test: a blocked truncate now delays the test
    that is waiting for it instead of sabotaging the one already going. The
    only difference is that the last test's rows outlive the session, which
    costs nothing in a disposable test database.
    """
    async with test_engine.begin() as conn:
        await conn.execute(text(f"TRUNCATE TABLE {', '.join(_TABLES)} RESTART IDENTITY CASCADE"))
    yield


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
