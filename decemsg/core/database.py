"""DeceMSG database module."""
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from pathlib import Path

from decemsg.core.config import get_config


class Base(DeclarativeBase):
    """Base class for all database models."""
    pass


# Database engine and session factory
_engine = None
_async_session_factory = None


def get_database_url() -> str:
    """Get database URL from configuration."""
    config = get_config()
    db_config = config.database
    
    if db_config.type == "sqlite":
        # Ensure data directory exists
        db_path = Path(db_config.path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        return f"sqlite+aiosqlite:///{db_config.path}"
    elif db_config.type == "postgresql":
        return f"postgresql+asyncpg://{db_config.path}"
    else:
        raise ValueError(f"Unsupported database type: {db_config.type}")


def get_engine():
    """Get or create database engine."""
    global _engine
    if _engine is None:
        _engine = create_async_engine(
            get_database_url(),
            echo=False,
            future=True,
        )
    return _engine


def get_session_factory():
    """Get or create async session factory."""
    global _async_session_factory
    if _async_session_factory is None:
        _async_session_factory = async_sessionmaker(
            get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _async_session_factory


async def get_db() -> AsyncSession:
    """Dependency for getting database session."""
    session_factory = get_session_factory()
    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    """Initialize database tables and backfill stable identities."""
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Existing users predate UserIdentity. Backfill their stable identity once.
    from decemsg.models.user import User
    from decemsg.models.identity import UserIdentity

    session_factory = get_session_factory()
    async with session_factory() as session:
        result = await session.execute(select(User))
        users = result.scalars().all()
        for user in users:
            identity_result = await session.execute(
                select(UserIdentity).where(UserIdentity.user_id == user.id)
            )
            if identity_result.scalar_one_or_none() is None:
                session.add(
                    UserIdentity(
                        user_id=user.id,
                        username=user.username,
                        domain=user.domain,
                    )
                )
        await session.commit()


async def close_db():
    """Close database connections."""
    global _engine, _async_session_factory
    if _engine:
        await _engine.dispose()
        _engine = None
        _async_session_factory = None
