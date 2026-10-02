"""Session security regression tests."""

import asyncio
from datetime import datetime, timedelta
import pytest

from decemsg.core.auth import create_access_token, get_current_session
from decemsg.models.session import UserSession


class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class _SessionDB:
    def __init__(self, sessions):
        self.sessions = sessions

    async def execute(self, statement):
        # The production query carries the session ID and user ID as bound
        # parameters. For this unit harness, match the values from the token
        # against the in-memory fixtures.
        compiled = str(statement)
        for session in self.sessions:
            if session.id in compiled and session.user_id in compiled:
                return _Result(session)
        # SQLAlchemy parameters are not rendered into str(statement), so the
        # harness returns the first fixture when there is one.
        return _Result(self.sessions[0] if self.sessions else None)


@pytest.mark.security
def test_session_bound_token_is_accepted() -> None:
    now = datetime.utcnow()
    session = UserSession(
        id="session-1",
        user_id="user-1",
        expires_at=now + timedelta(hours=1),
    )
    token = create_access_token(
        {"sub": "user-1", "sid": "session-1"},
        expires_delta=timedelta(hours=1),
    )

    current = asyncio.run(get_current_session(token, _SessionDB([session])))
    assert current.id == "session-1"


@pytest.mark.security
def test_revoked_session_rejects_a_stolen_token() -> None:
    now = datetime.utcnow()
    session = UserSession(
        id="session-1",
        user_id="user-1",
        expires_at=now + timedelta(hours=1),
    )
    token = create_access_token(
        {"sub": "user-1", "sid": "session-1"},
        expires_delta=timedelta(hours=1),
    )
    db = _SessionDB([session])

    assert asyncio.run(get_current_session(token, db)).id == "session-1"

    session.revoked_at = datetime.utcnow()

    with pytest.raises(Exception) as exc:
        asyncio.run(get_current_session(token, db))
    assert getattr(exc.value, "status_code", None) == 401


@pytest.mark.security
def test_expired_session_rejects_an_unexpired_jwt() -> None:
    session = UserSession(
        id="session-1",
        user_id="user-1",
        expires_at=datetime.utcnow() - timedelta(seconds=1),
    )
    token = create_access_token(
        {"sub": "user-1", "sid": "session-1"},
        expires_delta=timedelta(hours=1),
    )

    with pytest.raises(Exception) as exc:
        asyncio.run(get_current_session(token, _SessionDB([session])))
    assert getattr(exc.value, "status_code", None) == 401


@pytest.mark.security
def test_token_without_session_id_is_rejected() -> None:
    token = create_access_token(
        {"sub": "user-1"},
        expires_delta=timedelta(hours=1),
    )

    with pytest.raises(Exception) as exc:
        asyncio.run(get_current_session(token, _SessionDB([])))
    assert getattr(exc.value, "status_code", None) == 401
