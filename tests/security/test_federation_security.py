"""Federation security regression and contract tests.

TASK-002 establishes the reusable negative-security harness.  Some contract
tests are strict xfails because the corresponding enforcement is intentionally
implemented by later P0 tasks (TASK-003 through TASK-006 and TASK-020).  A
future implementation that unexpectedly makes one of these tests pass will
fail CI, forcing the contract annotation to be removed deliberately.
"""

import asyncio
import time
from unittest.mock import AsyncMock
from types import SimpleNamespace

import pytest
from fastapi import Request
from starlette.responses import Response

from decemsg.federation.auth_middleware import AuthResult, FederationAuthMiddleware
from decemsg.main import app
from decemsg.federation import router as federation_router
from decemsg.federation import (
    ChatSyncRequest,
    DeliveryReceipt,
    IncomingMessage,
    MessageDeleteRequest,
    MessageUpdateRequest,
    TypingIndicatorRequest,
    receive_delivery_receipt,
    receive_message,
    receive_message_delete,
    receive_message_update,
    receive_typing_indicator,
    sync_chat_from_federation,
    update_group_members,
)
from decemsg.federation.server_auth import (
    ServerKeyManager,
    ServerTrustStore,
    get_trust_store,
    reset_trust_store,
    verify_authenticated_request,
)


PROTECTED_ENDPOINTS = (
    ("/federation/messages", "POST"),
    ("/federation/receipts", "POST"),
    ("/federation/messages/update", "POST"),
    ("/federation/messages/delete", "POST"),
    ("/federation/chats/sync", "POST"),
    ("/federation/chats/group/members", "POST"),
    ("/federation/files", "POST"),
    ("/federation/typing", "POST"),
)


def _request(
    path: str,
    method: str = "POST",
    body: bytes = b"{}",
    headers: dict[str, str] | None = None,
) -> Request:
    header_items = [
        (key.lower().encode("latin-1"), value.encode("latin-1"))
        for key, value in (headers or {}).items()
    ]
    sent = False

    async def receive() -> dict:
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": header_items,
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 12345),
        "root_path": "",
    }
    return Request(scope, receive)


async def _dispatch(
    request: Request,
    middleware: FederationAuthMiddleware,
) -> Response:
    call_next = AsyncMock(return_value=Response(status_code=204))
    return await middleware.dispatch(request, call_next)


def _signed_headers(
    manager: ServerKeyManager,
    *,
    domain: str = "remote.example",
    timestamp: int | None = None,
) -> dict[str, str]:
    timestamp = int(time.time()) if timestamp is None else timestamp
    body = "{}"
    path = "/federation/messages"
    method = "POST"
    request_id = "test-request-id"
    key_id = manager.get_key_id()
    payload = f"{method}:{path}:{timestamp}:{request_id}:{domain}:{key_id}:"
    import hashlib

    payload += hashlib.sha256(body.encode()).hexdigest()
    signature = manager.sign_data(payload)
    reset_trust_store()
    get_trust_store().add_key(domain, manager.get_public_key_pem())
    return {
        "X-Server-Signature": signature,
        "X-Server-Timestamp": str(timestamp),
        "X-Server-Request-ID": request_id,
        "X-Server-Public-Key": manager.get_public_key_pem(),
        "X-Server-Key-ID": key_id,
        "X-Server-Domain": domain,
    }


@pytest.mark.security
def test_federation_auth_middleware_is_registered() -> None:
    """Application startup must register the federation auth middleware."""
    assert any(
        middleware.cls is FederationAuthMiddleware
        for middleware in app.user_middleware
    )


@pytest.mark.security
def test_every_non_public_federation_route_requires_authentication() -> None:
    """All federation router groups are deny-by-default protected."""
    public_prefixes = FederationAuthMiddleware.PUBLIC_PATHS
    middleware = FederationAuthMiddleware(AsyncMock())

    routes = [
        route
        for route in federation_router.routes
        if getattr(route, "path", "").startswith("/federation/")
    ]
    assert routes

    for route in routes:
        path = route.path
        if any(path.startswith(prefix) for prefix in public_prefixes):
            continue

        methods = sorted(getattr(route, "methods", {"GET"}))
        method = methods[0]
        response = asyncio.run(_dispatch(_request(path, method), middleware))
        assert response.status_code == 401, (
            f"Federation route {method} {path} bypassed authentication"
        )


@pytest.mark.security
def test_valid_authenticated_request_reaches_protected_handler(tmp_path, monkeypatch) -> None:
    """A valid signed request passes middleware to the endpoint handler."""
    monkeypatch.chdir(tmp_path)
    manager = ServerKeyManager()
    headers = _signed_headers(manager)
    request = _request(
        "/federation/messages",
        "POST",
        body=b"{}",
        headers=headers,
    )
    call_next = AsyncMock(return_value=Response(status_code=204))
    middleware = FederationAuthMiddleware(AsyncMock())

    response = asyncio.run(middleware.dispatch(request, call_next))

    assert response.status_code == 204
    call_next.assert_awaited_once()
    auth = request.state.federation_auth
    assert auth.is_authenticated is True
    assert auth.server_domain == "remote.example"


@pytest.mark.security
def test_unknown_federation_route_is_protected_by_default() -> None:
    """New federation routes must not silently become public."""
    middleware = FederationAuthMiddleware(AsyncMock())
    response = asyncio.run(
        _dispatch(_request("/federation/new-future-endpoint", "POST"), middleware)
    )
    assert response.status_code == 401


@pytest.mark.security
def test_explicit_discovery_route_remains_public() -> None:
    """Protocol discovery metadata must remain reachable without federation auth."""
    middleware = FederationAuthMiddleware(AsyncMock())
    response = asyncio.run(
        _dispatch(_request("/federation/.well-known/nodeinfo", "GET"), middleware)
    )
    assert response.status_code == 204


@pytest.mark.security
@pytest.mark.parametrize("path,method", PROTECTED_ENDPOINTS)
async def test_protected_federation_endpoints_require_authentication(
    path: str,
    method: str,
) -> None:
    """Protected federation operations reject requests without credentials."""
    middleware = FederationAuthMiddleware(AsyncMock())
    response = asyncio.run(_dispatch(_request(path, method), middleware))

    assert response.status_code == 401


@pytest.mark.security
def test_valid_federation_signature_is_accepted(tmp_path, monkeypatch) -> None:
    """The baseline must prove that correctly signed federation requests work."""
    monkeypatch.chdir(tmp_path)
    manager = ServerKeyManager()
    headers = _signed_headers(manager)

    assert (
        verify_authenticated_request(
            method="POST",
            path="/federation/messages",
            body="{}",
            headers=headers,
        )
        is True
    )


@pytest.mark.security
def test_invalid_federation_signature_is_rejected(tmp_path, monkeypatch) -> None:
    """A malformed signature must never authenticate a federation request."""
    monkeypatch.chdir(tmp_path)
    manager = ServerKeyManager()
    headers = _signed_headers(manager)
    headers["X-Server-Signature"] = "not-a-valid-signature"

    assert (
        verify_authenticated_request(
            method="POST",
            path="/federation/messages",
            body="{}",
            headers=headers,
        )
        is False
    )


@pytest.mark.security
def test_tampered_federation_body_invalidates_signature(tmp_path, monkeypatch) -> None:
    """Changing a signed request body must invalidate the signature."""
    monkeypatch.chdir(tmp_path)
    manager = ServerKeyManager()
    headers = _signed_headers(manager)

    assert (
        verify_authenticated_request(
            method="POST",
            path="/federation/messages",
            body='{"tampered":true}',
            headers=headers,
        )
        is False
    )


@pytest.mark.security
def test_incorrect_server_domain_is_rejected(tmp_path, monkeypatch) -> None:
    """A valid signature for another domain cannot satisfy an expected domain."""
    monkeypatch.chdir(tmp_path)
    manager = ServerKeyManager()
    headers = _signed_headers(manager, domain="attacker.example")

    assert (
        verify_authenticated_request(
            method="POST",
            path="/federation/messages",
            body="{}",
            headers=headers,
            server_domain="trusted.example",
        )
        is False
    )


@pytest.mark.security
def test_stale_federation_request_is_rejected(tmp_path, monkeypatch) -> None:
    """Federation authentication must enforce a bounded request lifetime."""
    monkeypatch.chdir(tmp_path)
    manager = ServerKeyManager()
    stale = int(time.time()) - 301
    headers = _signed_headers(manager, timestamp=stale)

    assert (
        verify_authenticated_request(
            method="POST",
            path="/federation/messages",
            body="{}",
            headers=headers,
        )
        is False
    )


@pytest.mark.security
def test_missing_request_id_fails_closed(tmp_path, monkeypatch) -> None:
    """Signed requests without a replay-protection identifier are rejected."""
    monkeypatch.chdir(tmp_path)
    manager = ServerKeyManager()
    headers = _signed_headers(manager)
    headers.pop("X-Server-Request-ID")

    assert not verify_authenticated_request(
        method="POST",
        path="/federation/messages",
        body="{}",
        headers=headers,
    )


@pytest.mark.security
def test_signed_security_fields_cannot_be_tampered(tmp_path, monkeypatch) -> None:
    """Changing domain or key ID after signing invalidates authentication."""
    monkeypatch.chdir(tmp_path)
    manager = ServerKeyManager()
    headers = _signed_headers(manager)
    headers["X-Server-Key-ID"] = "sha256:tampered"

    assert not verify_authenticated_request(
        method="POST",
        path="/federation/messages",
        body="{}",
        headers=headers,
    )


@pytest.mark.security
def test_missing_federation_credentials_fail_closed() -> None:
    """Missing authentication material must never be treated as anonymous trust."""
    assert (
        verify_authenticated_request(
            method="POST",
            path="/federation/messages",
            body="{}",
            headers={},
        )
        is False
    )



@pytest.mark.security
def test_self_asserted_server_key_cannot_claim_a_trusted_domain(
    tmp_path,
    monkeypatch,
) -> None:
    """A key is accepted only when explicitly bound to the claimed domain."""
    monkeypatch.chdir(tmp_path)
    reset_trust_store()
    manager = ServerKeyManager()
    headers = _signed_headers(manager, domain="trusted.example")
    headers["X-Server-Domain"] = "other.example"

    assert not verify_authenticated_request(
        method="POST",
        path="/federation/messages",
        body="{}",
        headers=headers,
        server_domain="trusted.example",
    )


@pytest.mark.security
def test_untrusted_key_is_rejected_even_with_a_valid_signature(
    tmp_path,
    monkeypatch,
) -> None:
    """Possession of a signing key is not sufficient to establish trust."""
    monkeypatch.chdir(tmp_path)
    reset_trust_store()
    manager = ServerKeyManager()
    timestamp = int(time.time())
    body = "{}"
    path = "/federation/messages"
    import hashlib
    payload = f"POST:{path}:{timestamp}:{hashlib.sha256(body.encode()).hexdigest()}"
    headers = {
        "X-Server-Signature": manager.sign_data(payload),
        "X-Server-Timestamp": str(timestamp),
        "X-Server-Public-Key": manager.get_public_key_pem(),
        "X-Server-Key-ID": manager.get_key_id(),
        "X-Server-Domain": "untrusted.example",
    }

    assert not verify_authenticated_request(
        method="POST",
        path=path,
        body=body,
        headers=headers,
    )


@pytest.mark.security
def test_trusted_key_rotation_accepts_new_key_and_rejects_revoked_old_key(
    tmp_path,
    monkeypatch,
) -> None:
    """Multiple pinned keys permit controlled rotation and revocation."""
    monkeypatch.chdir(tmp_path)
    store = ServerTrustStore()
    old_manager = ServerKeyManager()
    old_record = store.add_key("remote.example", old_manager.get_public_key_pem())
    from pathlib import Path
    Path("./data/server_identity_key.pem").unlink()
    new_manager = ServerKeyManager()
    new_record = store.add_key("remote.example", new_manager.get_public_key_pem())

    assert old_record.key_id != new_record.key_id
    assert store.is_trusted("remote.example", old_record.key_id, old_record.public_key_pem)
    assert store.is_trusted("remote.example", new_record.key_id, new_record.public_key_pem)

    assert store.revoke_key("remote.example", old_record.key_id)
    assert not store.is_trusted("remote.example", old_record.key_id, old_record.public_key_pem)
    assert store.is_trusted("remote.example", new_record.key_id, new_record.public_key_pem)


@pytest.mark.security
def test_expired_or_not_yet_valid_trusted_key_is_rejected(tmp_path, monkeypatch) -> None:
    """Trust records enforce their validity window."""
    from datetime import datetime, timedelta

    monkeypatch.chdir(tmp_path)
    manager = ServerKeyManager()
    store = ServerTrustStore()
    now = datetime.utcnow()
    record = store.add_key(
        "remote.example",
        manager.get_public_key_pem(),
        not_before=now + timedelta(minutes=1),
        expires_at=now + timedelta(minutes=2),
    )

    assert not store.is_trusted(
        "remote.example", record.key_id, record.public_key_pem, now=now
    )
    assert store.is_trusted(
        "remote.example",
        record.key_id,
        record.public_key_pem,
        now=now + timedelta(minutes=1, seconds=1),
    )
    assert not store.is_trusted(
        "remote.example",
        record.key_id,
        record.public_key_pem,
        now=now + timedelta(minutes=2),
    )


@pytest.mark.security
def test_replayed_valid_federation_request_is_rejected(
    tmp_path,
    monkeypatch,
) -> None:
    """Replaying an otherwise valid request must not produce another effect."""
    monkeypatch.chdir(tmp_path)
    manager = ServerKeyManager()
    headers = _signed_headers(manager)

    first = verify_authenticated_request(
        method="POST",
        path="/federation/messages",
        body="{}",
        headers=headers,
    )
    second = verify_authenticated_request(
        method="POST",
        path="/federation/messages",
        body="{}",
        headers=headers,
    )

    assert first is True
    assert second is False


@pytest.mark.security
def test_unauthorized_message_injection_is_rejected() -> None:
    """A server cannot submit a message claiming another server's domain."""
    auth = AuthResult(is_authenticated=True, server_domain="trusted.example")
    payload = IncomingMessage(
        from_user="alice",
        from_domain="attacker.example",
        to_user="bob",
        content="injected",
        event={
            "event_type": "message",
            "protocol_version": "1",
            "origin_server": "attacker.example",
            "origin_key_id": "attacker-key",
            "actor_identity": "alice#attacker.example",
            "target_identity": "bob#local.example",
            "conversation_id": "chat-1",
            "created_at": "2026-10-02T00:00:00",
            "sequence": 0,
            "message_type": "text",
            "ciphertext": "injected",
            "signature": "invalid",
        },
    )
    with pytest.raises(Exception) as exc:
        asyncio.run(receive_message(payload, AsyncMock(), auth))
    assert getattr(exc.value, "status_code", None) == 403


@pytest.mark.security
def test_forged_delivery_receipt_is_rejected() -> None:
    """A server cannot forge a receipt for an actor outside its domain."""
    auth = AuthResult(is_authenticated=True, server_domain="trusted.example")
    receipt = DeliveryReceipt(
        message_id="message-1",
        chat_id="chat-1",
        status="read",
        user_id="victim#attacker.example",
        timestamp="2026-01-01T00:00:00Z",
    )
    with pytest.raises(Exception) as exc:
        asyncio.run(receive_delivery_receipt(receipt, AsyncMock(), auth))
    assert getattr(exc.value, "status_code", None) == 403


@pytest.mark.security
def test_unauthorized_message_update_is_rejected() -> None:
    """A remote server cannot edit a message owned by another server."""
    auth = AuthResult(is_authenticated=True, server_domain="attacker.example")
    message = SimpleNamespace(chat_id="chat-1", sender_id="alice#trusted.example")
    db = AsyncMock()
    db.execute.return_value = SimpleNamespace(scalar_one_or_none=lambda: message)
    update = MessageUpdateRequest(
        message_id="message-1",
        chat_id="chat-1",
        content="tampered",
    )

    with pytest.raises(Exception) as exc:
        asyncio.run(receive_message_update(update, db, auth))
    assert getattr(exc.value, "status_code", None) == 403


@pytest.mark.security
def test_unauthorized_message_delete_is_rejected() -> None:
    """A remote server cannot delete a message owned by another server."""
    auth = AuthResult(is_authenticated=True, server_domain="attacker.example")
    message = SimpleNamespace(chat_id="chat-1", sender_id="alice#trusted.example")
    db = AsyncMock()
    db.execute.return_value = SimpleNamespace(scalar_one_or_none=lambda: message)
    delete = MessageDeleteRequest(message_id="message-1", chat_id="chat-1")

    with pytest.raises(Exception) as exc:
        asyncio.run(receive_message_delete(delete, db, auth))
    assert getattr(exc.value, "status_code", None) == 403


@pytest.mark.security
def test_federated_chat_sync_cannot_add_remote_actor_from_another_domain() -> None:
    """Chat sync is scoped to the authenticated origin domain."""
    auth = AuthResult(is_authenticated=True, server_domain="trusted.example")
    sync = ChatSyncRequest(chat_id="chat-1", members=["alice#attacker.example"])

    with pytest.raises(Exception) as exc:
        asyncio.run(sync_chat_from_federation(sync, AsyncMock(), auth))
    assert getattr(exc.value, "status_code", None) == 403


@pytest.mark.security
def test_group_member_update_cannot_manage_another_domain() -> None:
    """Group membership operations cannot target actors owned by another server."""
    auth = AuthResult(is_authenticated=True, server_domain="trusted.example")
    db = AsyncMock()

    with pytest.raises(Exception) as exc:
        asyncio.run(
            update_group_members(
                "chat-1",
                "add",
                ["alice#attacker.example"],
                db,
                auth,
            )
        )
    assert getattr(exc.value, "status_code", None) == 403


@pytest.mark.security
def test_typing_indicator_cannot_claim_another_domain() -> None:
    """Typing events must be attributed to the authenticated origin."""
    auth = AuthResult(is_authenticated=True, server_domain="trusted.example")
    typing = TypingIndicatorRequest(
        chat_id="chat-1",
        user_id="alice#attacker.example",
        is_typing=True,
    )

    with pytest.raises(Exception) as exc:
        asyncio.run(receive_typing_indicator(typing, AsyncMock(), auth))
    assert getattr(exc.value, "status_code", None) == 403
