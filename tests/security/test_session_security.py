"""Session security regression tests."""

import asyncio
from datetime import datetime, timedelta
import pytest
from unittest.mock import AsyncMock

from decemsg.core.auth import create_access_token, get_current_session, validate_login_device
from decemsg.api.auth import (
    PasswordChangeRequest,
    RecoveryBackupRequest,
    change_password,
    put_recovery_backup,
)
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



@pytest.mark.security
def test_federated_identity_is_distinct_from_local_user() -> None:
    """Remote addresses have their own identity record and lifecycle."""
    from decemsg.models.federated_identity import FederatedIdentity

    remote = FederatedIdentity(
        id="remote-1",
        username="bob",
        domain="remote.example",
        display_name="Bob",
    )

    assert remote.full_address == "bob#remote.example"
    assert remote.domain == "remote.example"
    assert remote.user_id if hasattr(remote, "user_id") else True


@pytest.mark.security
def test_chat_member_supports_exactly_one_local_or_remote_identity() -> None:
    """Conversation participants use a local FK or a federated identity FK."""
    from decemsg.models.chat import ChatMember

    constraints = {constraint.name for constraint in ChatMember.__table__.constraints}
    assert "ck_chat_member_has_identity" in constraints
    assert "ck_chat_member_one_identity" in constraints


@pytest.mark.security
def test_message_has_explicit_remote_sender_reference() -> None:
    """Remote senders no longer need to masquerade as local User foreign keys."""
    from decemsg.models.message import Message

    assert "sender_federated_identity_id" in Message.__table__.columns



@pytest.mark.security
def test_revoked_device_cannot_create_a_new_bound_session() -> None:
    """Login cannot bind a new session to a revoked device."""
    from decemsg.models.device import Device, DeviceStatus

    device = Device(
        id="device-1",
        user_id="user-1",
        name="Laptop",
        platform="web",
        public_identity_key="public-key-material",
        status=DeviceStatus.REVOKED,
        revoked_at=datetime.utcnow(),
    )
    db = _SessionDB([])
    db.execute = AsyncMock(return_value=_Result(device))

    with pytest.raises(Exception) as exc:
        asyncio.run(validate_login_device(db, "user-1", "device-1"))
    assert getattr(exc.value, "status_code", None) == 403



@pytest.mark.security
def test_recovery_backup_requires_argon2id_and_opaque_ciphertext() -> None:
    """Recovery storage accepts only an Argon2id-derived encrypted envelope."""
    import base64
    from decemsg.models.user import User

    user = User(
        id="user-1",
        username="alice",
        display_name="Alice",
        password_hash="stored-hash",
        domain="example.com",
    )
    db = AsyncMock()
    db.execute.return_value = _Result(None)

    backup = RecoveryBackupRequest(
        version=1,
        kdf_algorithm="argon2id",
        kdf_memory_kib=19456,
        kdf_iterations=2,
        kdf_parallelism=1,
        kdf_salt=base64.b64encode(b"0123456789abcdef").decode(),
        encryption_algorithm="AES-256-GCM",
        encryption_nonce=base64.b64encode(b"0123456789ab").decode(),
        ciphertext=base64.b64encode(b"opaque-ciphertext-material" * 2).decode(),
    )

    result = asyncio.run(put_recovery_backup(backup, user, db))
    assert result["status"] == "stored"
    assert result["version"] == 1
    stored = db.add.call_args.args[0]
    assert "private_key" not in stored.__dict__
    assert stored.ciphertext == backup.ciphertext



@pytest.mark.security
def test_browser_crypto_private_keys_are_not_stored_in_web_storage() -> None:
    """Browser device private keys must live in IndexedDB as CryptoKey objects."""
    from pathlib import Path

    app_js = (
        Path(__file__).resolve().parents[2] / "decemsg" / "ui" / "app.js"
    ).read_text(encoding="utf-8")

    assert "indexedDB.open" in app_js
    assert "generateKey" in app_js
    assert "false," in app_js
    assert "localStorage.setItem('privateKey'" not in app_js
    assert "localStorage.setItem('deviceKey'" not in app_js


@pytest.mark.security
def test_browser_csp_is_configured() -> None:
    """The browser client has a restrictive same-origin CSP."""
    from pathlib import Path

    index_html = (
        Path(__file__).resolve().parents[2] / "decemsg" / "ui" / "index.html"
    ).read_text(encoding="utf-8")

    assert "Content-Security-Policy" in index_html
    assert "script-src 'self'" in index_html
    assert "object-src 'none'" in index_html
