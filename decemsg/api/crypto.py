"""Authenticated client E2EE transport endpoints.

The server stores only public device/key material and opaque encrypted
to-device envelopes. Private E2EE state stays on client devices.
"""

import json
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from decemsg.core.auth import get_current_session, get_current_user
from decemsg.core.database import get_db
from decemsg.models.chat import ChatMember
from decemsg.models.device import Device, DeviceStatus
from decemsg.models.user import User
from decemsg.models.session import UserSession
from decemsg.models.crypto import CryptoDeviceState, CryptoToDeviceMessage

router = APIRouter(prefix="/api/crypto", tags=["E2EE"])


class CryptoRequest(BaseModel):
    request_type: str = Field(..., pattern=r"^(keys_upload|keys_query|keys_claim|to_device)$")
    request_id: str = Field(..., min_length=1, max_length=255)
    body: dict[str, Any] = Field(default_factory=dict)
    event_type: str | None = Field(None, max_length=255)
    chat_id: str | None = Field(None, max_length=36)


def _matrix_user_id(user: User) -> str:
    return "@" + user.username + ":" + user.domain


async def _require_current_device(
    current_user: User,
    current_session: UserSession,
    db: AsyncSession,
) -> Device:
    if current_session.user_id != current_user.id or not current_session.device_id:
        raise HTTPException(status_code=401, detail="Session is not bound to a device")

    result = await db.execute(
        select(Device).where(
            Device.id == current_session.device_id,
            Device.user_id == current_user.id,
            Device.status == DeviceStatus.ACTIVE,
        )
    )
    device = result.scalar_one_or_none()
    if device is None:
        raise HTTPException(status_code=401, detail="Active device not found")
    return device


async def _require_chat_membership(
    chat_id: str,
    current_user_id: str,
    target_user_ids: set[str],
    db: AsyncSession,
) -> None:
    result = await db.execute(select(ChatMember).where(ChatMember.chat_id == chat_id))
    members = result.scalars().all()
    local_member_ids = {m.user_id for m in members if m.user_id}
    if current_user_id not in local_member_ids or not target_user_ids.issubset(local_member_ids):
        raise HTTPException(status_code=403, detail="Crypto operation is outside the chat")


async def _keys_query(body: dict[str, Any], db: AsyncSession) -> dict[str, Any]:
    requested = body.get("device_keys", {})
    response: dict[str, Any] = {"device_keys": {}, "failures": {}}
    for matrix_user_id in requested:
        if not isinstance(matrix_user_id, str) or not matrix_user_id.startswith("@"):
            continue
        parts = matrix_user_id[1:].split(":", 1)
        if len(parts) != 2:
            continue
        username, domain = parts
        result = await db.execute(
            select(User).where(
                User.username == username,
                User.domain == domain,
                User.is_active.is_(True),
            )
        )
        user = result.scalar_one_or_none()
        if user is None:
            continue
        device_result = await db.execute(
            select(CryptoDeviceState)
            .join(Device, Device.id == CryptoDeviceState.device_id)
            .where(
                CryptoDeviceState.user_id == user.id,
                Device.status == DeviceStatus.ACTIVE,
            )
        )
        states = device_result.scalars().all()
        response["device_keys"][matrix_user_id] = {
            json.loads(state.device_keys).get("device_id", ""): json.loads(state.device_keys)
            for state in states
        }
    return response


async def _keys_claim(body: dict[str, Any], db: AsyncSession) -> dict[str, Any]:
    requested = body.get("one_time_keys", {})
    response: dict[str, Any] = {"one_time_keys": {}, "failures": {}}

    for matrix_user_id, devices in requested.items():
        if not isinstance(devices, dict) or not isinstance(matrix_user_id, str):
            continue
        parts = matrix_user_id[1:].split(":", 1) if matrix_user_id.startswith("@") else []
        if len(parts) != 2:
            continue
        username, domain = parts
        user_result = await db.execute(
            select(User).where(User.username == username, User.domain == domain)
        )
        user = user_result.scalar_one_or_none()
        if user is None:
            continue

        for device_id, algorithm in devices.items():
            state_result = await db.execute(
                select(CryptoDeviceState)
                .join(Device, Device.id == CryptoDeviceState.device_id)
                .where(
                    CryptoDeviceState.user_id == user.id,
                    CryptoDeviceState.device_id == device_id,
                    Device.status == DeviceStatus.ACTIVE,
                )
            )
            state = state_result.scalar_one_or_none()
            if state is None:
                continue

            one_time = json.loads(state.one_time_keys)
            selected_name = None
            selected_key = None
            for key_name, key_value in one_time.items():
                if str(algorithm) in key_name:
                    selected_name, selected_key = key_name, key_value
                    break
            if selected_name is None and one_time:
                selected_name, selected_key = next(iter(one_time.items()))
            if selected_name is None:
                continue

            del one_time[selected_name]
            state.one_time_keys = json.dumps(one_time, separators=(",", ":"))
            state.updated_at = datetime.utcnow()
            response["one_time_keys"].setdefault(matrix_user_id, {}).setdefault(device_id, {})[
                selected_name
            ] = selected_key

    await db.commit()
    return response


@router.post("/requests")
async def process_crypto_request(
    request: CryptoRequest,
    current_user: User = Depends(get_current_user),
    current_session: UserSession = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    device = await _require_current_device(current_user, current_session, db)
    matrix_user_id = _matrix_user_id(current_user)

    if request.request_type == "keys_upload":
        device_keys = request.body.get("device_keys")
        if not isinstance(device_keys, dict) or device_keys.get("user_id") != matrix_user_id:
            raise HTTPException(status_code=403, detail="Device keys are not owned by current user")
        if device_keys.get("device_id") != device.id:
            raise HTTPException(status_code=403, detail="Device keys are not owned by current device")

        state_result = await db.execute(
            select(CryptoDeviceState).where(CryptoDeviceState.device_id == device.id)
        )
        state = state_result.scalar_one_or_none()
        if state is None:
            state = CryptoDeviceState(
                user_id=current_user.id,
                device_id=device.id,
                device_keys=json.dumps(device_keys, separators=(",", ":")),
            )
            db.add(state)
        else:
            state.device_keys = json.dumps(device_keys, separators=(",", ":"))

        state.one_time_keys = json.dumps(
            request.body.get("one_time_keys", {}), separators=(",", ":")
        )
        state.fallback_keys = json.dumps(
            request.body.get("fallback_keys", {}), separators=(",", ":")
        )
        state.updated_at = datetime.utcnow()
        await db.commit()

        one_time_keys = request.body.get("one_time_keys", {})
        return {
            "one_time_key_counts": {
                "signed_curve25519": sum(
                    1 for key in one_time_keys if str(key).startswith("signed_curve25519:")
                ),
                "curve25519": sum(
                    1 for key in one_time_keys if str(key).startswith("curve25519:")
                ),
            }
        }

    if request.request_type in {"keys_query", "keys_claim"}:
        if not request.chat_id:
            raise HTTPException(status_code=400, detail="chat_id is required for key discovery")
        if request.request_type == "keys_query":
            target_users = set(request.body.get("device_keys", {}).keys())
            await _require_chat_membership(request.chat_id, current_user.id, target_users, db)
            return await _keys_query(request.body, db)
        target_users = set(request.body.get("one_time_keys", {}).keys())
        await _require_chat_membership(request.chat_id, current_user.id, target_users, db)
        return await _keys_claim(request.body, db)

    if request.request_type == "to_device":
        if not request.chat_id or not request.event_type:
            raise HTTPException(status_code=400, detail="chat_id and event_type are required")
        messages = request.body.get("messages", {})
        if not isinstance(messages, dict):
            raise HTTPException(status_code=400, detail="Invalid to-device messages")

        await _require_chat_membership(request.chat_id, current_user.id, set(messages.keys()), db)

        for recipient_matrix_id, devices in messages.items():
            if not isinstance(recipient_matrix_id, str) or not recipient_matrix_id.startswith("@"):
                continue
            parts = recipient_matrix_id[1:].split(":", 1)
            if len(parts) != 2:
                continue
            username, domain = parts
            user_result = await db.execute(
                select(User).where(User.username == username, User.domain == domain)
            )
            recipient = user_result.scalar_one_or_none()
            if recipient is None or not isinstance(devices, dict):
                continue

            for recipient_device_id, content in devices.items():
                if recipient_device_id == "*":
                    device_result = await db.execute(
                        select(Device).where(
                            Device.user_id == recipient.id,
                            Device.status == DeviceStatus.ACTIVE,
                        )
                    )
                    recipient_device_ids = [item.id for item in device_result.scalars().all()]
                else:
                    recipient_device_ids = [recipient_device_id]

                for target_device_id in recipient_device_ids:
                    target_device_result = await db.execute(
                        select(Device).where(
                            Device.id == target_device_id,
                            Device.user_id == recipient.id,
                            Device.status == DeviceStatus.ACTIVE,
                        )
                    )
                    if target_device_result.scalar_one_or_none() is None:
                        continue

                    db.add(
                        CryptoToDeviceMessage(
                            sender_user_id=current_user.id,
                            recipient_user_id=recipient.id,
                            recipient_device_id=target_device_id,
                            event_type=request.event_type,
                            content=(
                                json.dumps(content, separators=(",", ":"))
                                if not isinstance(content, str)
                                else content
                            ),
                            transaction_id=request.request_id,
                        )
                    )

        await db.commit()
        return {}

    raise HTTPException(status_code=400, detail="Unsupported crypto request")


@router.get("/to-device")
async def get_to_device_events(
    current_user: User = Depends(get_current_user),
    current_session: UserSession = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    device = await _require_current_device(current_user, current_session, db)
    result = await db.execute(
        select(CryptoToDeviceMessage)
        .where(
            CryptoToDeviceMessage.recipient_user_id == current_user.id,
            CryptoToDeviceMessage.recipient_device_id == device.id,
            CryptoToDeviceMessage.delivered_at.is_(None),
        )
        .order_by(CryptoToDeviceMessage.created_at.asc())
        .limit(100)
    )
    events = result.scalars().all()

    sender_ids = {event.sender_user_id for event in events}
    sender_result = await db.execute(select(User).where(User.id.in_(sender_ids))) if sender_ids else None
    sender_map = {user.id: _matrix_user_id(user) for user in (sender_result.scalars().all() if sender_result else [])}

    return {
        "events": [
            {
                "id": event.id,
                "sender": sender_map.get(event.sender_user_id),
                "event_type": event.event_type,
                "content": event.content,
                "transaction_id": event.transaction_id,
                "created_at": event.created_at.isoformat(),
            }
            for event in events
        ]
    }
