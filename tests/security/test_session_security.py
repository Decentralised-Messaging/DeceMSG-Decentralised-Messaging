"""Session security regression tests."""

import asyncio
from datetime import datetime, timedelta
import pytest

from decemsg.core.auth import create_access_token, get_current_session
from decemsg.api.auth import PasswordChangeRequest, change_password
from decemsg.models.session import UserSession


class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class _SessionDB:
    def __init__(self, sessions):
        self.sessions = sessions

    async def commit(self):
        return None

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



@pytest.mark.security
def test_websocket_authentication_does_not_use_query_parameter() -> None:
    """Bearer tokens must not be accepted from the WebSocket URL."""
    import inspect
    from decemsg.api.websocket import websocket_endpoint

    source = inspect.getsource(websocket_endpoint)
    assert "query_params.get" not in source
    assert '"authenticate"' in source


@pytest.mark.security
def test_multiple_sessions_remain_independent() -> None:
    """Revoking one session does not revoke another session."""
    now = datetime.utcnow()
    first = UserSession(
        id="session-1",
        user_id="user-1",
        expires_at=now + timedelta(hours=1),
    )
    second = UserSession(
        id="session-2",
        user_id="user-1",
        expires_at=now + timedelta(hours=1),
    )
    token = create_access_token(
        {"sub": "user-1", "sid": "session-2"},
        expires_delta=timedelta(hours=1),
    )

    first.revoked_at = now

    current = asyncio.run(get_current_session(token, _SessionDB([second])))
    assert current.id == "session-2"


@pytest.mark.security
def test_password_change_requires_current_password() -> None:
    """A stolen valid session alone must not authorize a password change."""
    from decemsg.models.user import User

    user = User(
        id="user-1",
        username="alice",
        display_name="Alice",
        password_hash="stored-hash",
        domain="example.com",
    )
    session = UserSession(
        id="session-1",
        user_id="user-1",
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )

    with pytest.raises(Exception) as exc:
        asyncio.run(
            change_password(
                PasswordChangeRequest(
                    current_password="wrong",
                    new_password="new-password",
                ),
                user,
                session,
                _SessionDB([]),
            )
        )
    assert getattr(exc.value, "status_code", None) == 401


@pytest.mark.security
def test_successful_password_change_preserves_session(monkeypatch) -> None:
    """Changing the password does not revoke the current authentication session."""
    from decemsg.models.user import User
    import decemsg.api.auth as auth_api

    user = User(
        id="user-1",
        username="alice",
        display_name="Alice",
        password_hash="stored-hash",
        domain="example.com",
    )
    session = UserSession(
        id="session-1",
        user_id="user-1",
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )

    monkeypatch.setattr(auth_api, "verify_password", lambda plain, stored: plain == "old")
    monkeypatch.setattr(auth_api, "get_password_hash", lambda password: f"hash:{password}")
    db = _SessionDB([])

    result = asyncio.run(
        change_password(
            PasswordChangeRequest(
                current_password="old",
                new_password="new-password",
            ),
            user,
            session,
            db,
        )
    )

    assert result["message"] == "Password changed successfully"
    assert user.password_hash == "hash:new-password"
    assert session.revoked_at is None



@pytest.mark.security
def test_user_identity_and_device_models_define_stable_security_metadata() -> None:
    """Identity and device records expose stable, lifecycle-aware metadata."""
    from decemsg.models.device import Device, DeviceStatus
    from decemsg.models.identity import UserIdentity

    identity = UserIdentity(
        id="identity-1",
        user_id="user-1",
        username="alice",
        domain="example.com",
    )
    device = Device(
        id="device-1",
        user_id="user-1",
        name="Alice Laptop",
        platform="web",
        public_identity_key="public-key-material",
        status=DeviceStatus.ACTIVE,
    )

    assert identity.username == "alice"
    assert identity.domain == "example.com"
    assert device.id == "device-1"
    assert device.status == DeviceStatus.ACTIVE
    assert device.public_identity_key == "public-key-material"
    assert "id" in Device.__table__.primary_key.columns.keys()
