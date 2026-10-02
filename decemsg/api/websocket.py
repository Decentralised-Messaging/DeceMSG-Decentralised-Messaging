"""DeceMSG WebSocket API endpoint."""
import asyncio
import json
from datetime import datetime
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from decemsg.core.database import get_db, get_session_factory
from decemsg.core.auth import decode_token, get_current_session
from decemsg.core.websocket import manager
from decemsg.core.config import get_config
from decemsg.models.user import User
from decemsg.models.session import UserSession
from decemsg.models.chat import Chat, ChatMember

router = APIRouter()


@router.websocket("/ws")
async def _session_is_active(session_id: str, user_id: str) -> bool:
    session_factory = get_session_factory()
    async with session_factory() as db:
        result = await db.execute(
            select(UserSession).where(
                UserSession.id == session_id,
                UserSession.user_id == user_id,
            )
        )
        session = result.scalar_one_or_none()
        return bool(
            session
            and session.revoked_at is None
            and session.expires_at > datetime.utcnow()
        )


async def _watch_websocket_session(
    websocket: WebSocket,
    session_id: str,
    user_id: str,
) -> None:
    """Disconnect a socket when its server-side session expires or is revoked."""
    try:
        while True:
            await asyncio.sleep(15)
            if not await _session_is_active(session_id, user_id):
                await websocket.close(code=4001, reason="Session expired or revoked")
                return
    except (WebSocketDisconnect, RuntimeError):
        return


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint authenticated by a session-bound bearer token."""
    await websocket.accept()

    # Browser WebSocket URLs must not carry bearer tokens in query parameters.
    # Authenticate as the first application frame instead.
    try:
        auth_frame = await asyncio.wait_for(websocket.receive_text(), timeout=10)
        auth_message = json.loads(auth_frame)
        if auth_message.get("type") != "authenticate":
            await websocket.close(code=4001, reason="Authentication required")
            return
        token = auth_message.get("token")
        if not isinstance(token, str) or not token:
            await websocket.close(code=4001, reason="Authentication required")
            return
    except (asyncio.TimeoutError, json.JSONDecodeError, WebSocketDisconnect):
        await websocket.close(code=4001, reason="Authentication required")
        return

    session_factory = get_session_factory()
    async with session_factory() as db:
        try:
            session = await get_current_session(token, db)
        except Exception:
            await websocket.close(code=4001, reason="Invalid session")
            return

        user_id = session.user_id
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if not user or not user.is_active:
            await websocket.close(code=4001, reason="User not found or inactive")
            return

        user.last_seen = datetime.utcnow()
        await db.commit()

    session_id = session.id
    session_watcher = asyncio.create_task(
        _watch_websocket_session(websocket, session_id, user_id)
    )

    await manager.connect(websocket, user_id)

    # Load user's chats and subscribe to their chat rooms.
    async with session_factory() as db:
        result = await db.execute(
            select(ChatMember).where(ChatMember.user_id == user_id)
        )
        memberships = result.scalars().all()
        for membership in memberships:
            manager.join_chat_room(user_id, membership.chat_id)

    await manager.broadcast_online_status(user_id, True)

    try:
        from decemsg.federation.offline_queue import notify_user_online
        await notify_user_online(user_id)
    except Exception as e:
        print(f"Error delivering offline messages: {e}")

    try:
        while True:
            data = await websocket.receive_text()

            try:
                message = json.loads(data)
            except json.JSONDecodeError:
                await websocket.send_json({
                    "type": "error",
                    "message": "Invalid JSON format",
                })
                continue

            message_type = message.get("type")

            if message_type == "authenticate":
                # Authentication is completed exactly once per connection.
                await websocket.send_json({"type": "error", "message": "Already authenticated"})

            elif message_type == "ping":
                await websocket.send_json({
                    "type": "pong",
                    "timestamp": datetime.utcnow().isoformat(),
                })

            elif message_type == "join_chat":
                chat_id = message.get("chat_id")
                if chat_id:
                    async with session_factory() as db:
                        result = await db.execute(
                            select(ChatMember).where(
                                ChatMember.chat_id == chat_id,
                                ChatMember.user_id == user_id,
                            )
                        )
                        if result.scalar_one_or_none():
                            manager.join_chat_room(user_id, chat_id)
                            await websocket.send_json({
                                "type": "joined_chat",
                                "chat_id": chat_id,
                            })
                        else:
                            await websocket.send_json({
                                "type": "error",
                                "message": "Not a member of this chat",
                            })

            elif message_type == "leave_chat":
                chat_id = message.get("chat_id")
                if chat_id:
                    async with session_factory() as db:
                        result = await db.execute(
                            select(ChatMember).where(
                                ChatMember.chat_id == chat_id,
                                ChatMember.user_id == user_id,
                            )
                        )
                        if result.scalar_one_or_none():
                            manager.leave_chat_room(user_id, chat_id)
                            await websocket.send_json({
                                "type": "left_chat",
                                "chat_id": chat_id,
                            })

            elif message_type == "typing":
                chat_id = message.get("chat_id")
                is_typing = message.get("is_typing", True)
                if chat_id:
                    async with session_factory() as db:
                        result = await db.execute(
                            select(ChatMember).where(
                                ChatMember.chat_id == chat_id,
                                ChatMember.user_id == user_id,
                            )
                        )
                        if result.scalar_one_or_none() is None:
                            await websocket.send_json({
                                "type": "error",
                                "message": "Not a member of this chat",
                            })
                            continue

                    typing_message = {
                        "type": "typing",
                        "chat_id": chat_id,
                        "user_id": user_id,
                        "is_typing": is_typing,
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                    await manager.broadcast_to_chat(
                        typing_message,
                        chat_id,
                        exclude_user=user_id,
                    )

                    try:
                        from decemsg.federation.federation_client import send_typing_indicator
                        await send_typing_indicator(chat_id, user_id, is_typing)
                    except Exception:
                        pass

            elif message_type == "read":
                chat_id = message.get("chat_id")
                message_id = message.get("message_id")
                if chat_id:
                    async with session_factory() as db:
                        result = await db.execute(
                            select(ChatMember).where(
                                ChatMember.chat_id == chat_id,
                                ChatMember.user_id == user_id,
                            )
                        )
                        membership = result.scalar_one_or_none()
                        if membership:
                            membership.last_read_message_id = message_id
                            await db.commit()

                            read_receipt = {
                                "type": "read_receipt",
                                "chat_id": chat_id,
                                "user_id": user_id,
                                "message_id": message_id,
                                "timestamp": datetime.utcnow().isoformat(),
                            }
                            await manager.broadcast_to_chat(
                                read_receipt,
                                chat_id,
                                exclude_user=user_id,
                            )
                        else:
                            await websocket.send_json({
                                "type": "error",
                                "message": "Not a member of this chat",
                            })

            else:
                await websocket.send_json({
                    "type": "error",
                    "message": f"Unknown message type: {message_type}",
                })

    except WebSocketDisconnect:
        pass
    finally:
        session_watcher.cancel()
        try:
            await session_watcher
        except asyncio.CancelledError:
            pass

        manager.disconnect(websocket, user_id)

        async with session_factory() as db:
            result = await db.execute(
                select(ChatMember).where(ChatMember.user_id == user_id)
            )
            memberships = result.scalars().all()
            for membership in memberships:
                manager.leave_chat_room(user_id, membership.chat_id)

        await manager.broadcast_online_status(user_id, False)


@router.get("/api/presence")
async def get_presence(
    user_ids: str,  # comma-separated list of user IDs
):
    """Get online status for a list of users."""
    ids = [uid.strip() for uid in user_ids.split(",")]
    presence = {}
    
    for uid in ids:
        presence[uid] = manager.is_user_online(uid)
    
    return presence
