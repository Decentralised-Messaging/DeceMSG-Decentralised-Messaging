"""Tests for deterministic message pagination cursors."""

from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException

from decemsg.api.messages import decode_message_cursor, encode_message_cursor


def test_message_cursor_round_trip() -> None:
    created_at = datetime(2026, 10, 3, 12, 30, 45, 123456)
    message_id = "message-2"

    cursor = encode_message_cursor(created_at, message_id)

    assert decode_message_cursor(cursor) == (created_at, message_id)


def test_message_cursor_supports_stable_forward_and_backward_ordering() -> None:
    created_at = datetime(2026, 10, 3, 12, 30)
    messages = [
        (created_at, "message-b"),
        (created_at, "message-a"),
        (created_at + timedelta(seconds=1), "message-c"),
    ]
    ordered = sorted(messages, key=lambda item: (item[0], item[1]))

    cursor = encode_message_cursor(*ordered[1])
    cursor_position = decode_message_cursor(cursor)

    before = [item for item in ordered if item < cursor_position]
    after = [item for item in ordered if item > cursor_position]

    assert before == [ordered[0]]
    assert after == [ordered[2]]


def test_message_cursor_rejects_malformed_value() -> None:
    with pytest.raises(HTTPException):
        decode_message_cursor("not-a-valid-cursor")
