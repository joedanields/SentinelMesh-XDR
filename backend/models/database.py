from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base
from typing import AsyncGenerator

from config import get_settings

settings = get_settings()

# SQLite doesn't support pool_size / max_overflow connection pool arguments
_is_sqlite = settings.database_url.startswith("sqlite")

_engine_kwargs: dict = {
    "echo": settings.debug,
    "pool_pre_ping": True,
}

if not _is_sqlite:
    _engine_kwargs["pool_size"] = 10
    _engine_kwargs["max_overflow"] = 20

engine = create_async_engine(settings.database_url, **_engine_kwargs)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

Base = declarative_base()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that provides an async database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Create all tables defined in the metadata."""
    # Import all models so SQLAlchemy knows about them before create_all
    import models.log_models  # noqa: F401
    import models.alert_models  # noqa: F401
    import models.incident_models  # noqa: F401
    import models.rule_models  # noqa: F401
    import models.user_models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    """Dispose the engine connection pool."""
    await engine.dispose()
