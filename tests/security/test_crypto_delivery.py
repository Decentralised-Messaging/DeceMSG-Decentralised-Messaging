"""Regression tests for durable offline E2EE to-device delivery."""

from types import SimpleNamespace

import pytest
from unittest.mock import AsyncMock

from decemsg.api.crypto import acknowledge_to_device_events, get_to_device_events


@pytest.mark.security
def test_to_device_delivery_retries_until_ack() -> None:
    user = SimpleNamespace(id="user-1")
    session = SimpleNamespace(user_id="user-1", device_id="device-1")
    device = SimpleNamespace(id="device-1")
    event = SimpleNamespace(
        id="event-1",
        sender_user_id="sender-1",
        recipient_user_id="user-1",
        recipient_device_id="device-1",
        event_type="m.room.encrypted",
        content='{"ciphertext":"opaque"}',
        transaction_id="txn-1",
        created_at=SimpleNamespace(isoformat=lambda: "2026-10-02T00:00:00"),
        delivered_at=None,
    )
    sender = SimpleNamespace(id="sender-1", username="alice", domain="example.com")

    def result(value):
        return SimpleNamespace(
            scalar_one_or_none=lambda: value,
            scalars=lambda: SimpleNamespace(all=lambda: [value] if value else []),
        )

    db = AsyncMock()
    db.execute.side_effect = [
        result(device),
        SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: [event])),
        SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: [sender])),
        result(device),
        SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: [event])),
        SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: [sender])),
    ]

    first = __import__("asyncio").run(get_to_device_events(user, session, db))
    second = __import__("asyncio").run(get_to_device_events(user, session, db))

    assert first["events"][0]["id"] == "event-1"
    assert second["events"][0]["id"] == "event-1"


@pytest.mark.security
def test_to_device_ack_marks_only_owned_pending_events() -> None:
    user = SimpleNamespace(id="user-1")
    session = SimpleNamespace(user_id="user-1", device_id="device-1")
    device = SimpleNamespace(id="device-1")
    event = SimpleNamespace(delivered_at=None)

    db = AsyncMock()
    db.execute.side_effect = [
        SimpleNamespace(scalar_one_or_none=lambda: device),
        SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: [event])),
    ]

    result = __import__("asyncio").run(
        acknowledge_to_device_events(["event-1"], user, session, db)
    )

    assert result == {"acknowledged": 1}
    assert event.delivered_at is not None
