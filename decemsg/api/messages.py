"""DeceMSG messages API endpoints."""
from typing import List, Optional
from datetime import datetime
import base64
import json

from fastapi import APIRouter, Depends, HTTPException, status, Query, UploadFile, File, Form, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_
from sqlalchemy.orm import selectinload
import aiofiles
import os
import uuid
import mimetypes

from decemsg.core.database import get_db
from decemsg.core.auth import get_current_user
from decemsg.core.config import get_config
from decemsg.core.rate_limiter import limiter, get_api_rate_limit
from decemsg.core.websocket import manager
from decemsg.models.user import User
from decemsg.models.chat import Chat, ChatMember
from decemsg.models.message import Message, MessageReaction, MessageType
from decemsg.federation.federation_client import is_federated_user, parse_user_id

router = APIRouter(prefix="/api", tags=["Messages"])


# Request/Response Models
class MessageCreate(BaseModel):
    """Message creation request.

    New message submission is ciphertext-only. The plaintext content field is
    retained only for backwards-compatible response typing and is rejected
    during creation.
    """
    content: str | None = Field(None, min_length=1)
    encrypted_content: str | None = Field(None, min_length=1, max_length=1_000_000)
    message_type: MessageType = MessageType.TEXT
    reply_to_id: str | None = None


class ReactionCreate(BaseModel):
    """Reaction creation request."""
    emoji: str = Field(..., min_length=1, max_length=10)


class MessageResponse(BaseModel):
    """Message response model."""
    id: str
    chat_id: str
    sender_id: str | None
    content: str
    message_type: str
    file_url: str | None
    file_name: str | None
    file_size: int | None
    created_at: str | None
    is_deleted: bool
    reply_to_id: str | None
    sender: dict | None
    reactions: dict = {}


def encode_message_cursor(created_at: datetime, message_id: str) -> str:
    """Encode the stable (created_at, id) pagination position."""
    payload = json.dumps({"created_at": created_at.isoformat(), "id": message_id}, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def decode_message_cursor(cursor: str) -> tuple[datetime, str]:
    """Decode a stable pagination cursor."""
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
        created_at = datetime.fromisoformat(payload["created_at"])
        message_id = payload["id"]
        if not isinstance(message_id, str) or not message_id:
            raise ValueError
        return created_at, message_id
    except (ValueError, KeyError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid message pagination cursor")



@router.get("/chats/{chat_id}/messages", response_model=List[MessageResponse])
async def get_messages(
    chat_id: str,
    limit: int = Query(50, ge=1, le=100),
    before: Optional[str] = Query(None, description="Opaque cursor for the page before this position"),
    after: Optional[str] = Query(None, description="Opaque cursor for the page after this position"),
    response: Response = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get messages with deterministic cursor pagination.

    Ordering is always by (created_at, id), with id breaking timestamp ties.
    before returns the preceding page; after returns the following page.
    """
    if before and after:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Use either before or after, not both")

    result = await db.execute(
        select(Chat).options(selectinload(Chat.members)).where(Chat.id == chat_id)
    )
    chat = result.scalar_one_or_none()
    if not chat:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Chat not found")

    if not any(m.user_id == current_user.id for m in chat.members):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this chat")

    query = select(Message).options(
        selectinload(Message.reactions),
        selectinload(Message.sender),
        selectinload(Message.sender_federated_identity),
    ).where(Message.chat_id == chat_id, Message.is_deleted == False)

    direction = "initial"
    if before:
        cursor_created_at, cursor_id = decode_message_cursor(before)
        direction = "before"
        query = query.where(
            or_(
                Message.created_at < cursor_created_at,
                and_(Message.created_at == cursor_created_at, Message.id < cursor_id),
            )
        ).order_by(Message.created_at.desc(), Message.id.desc()).limit(limit)
    elif after:
        cursor_created_at, cursor_id = decode_message_cursor(after)
        direction = "after"
        query = query.where(
            or_(
                Message.created_at > cursor_created_at,
                and_(Message.created_at == cursor_created_at, Message.id > cursor_id),
            )
        ).order_by(Message.created_at.asc(), Message.id.asc()).limit(limit)
    else:
        query = query.order_by(Message.created_at.desc(), Message.id.desc()).limit(limit)

    result = await db.execute(query)
    messages = list(result.scalars().all())
    if direction in {"initial", "before"}:
        messages.reverse()

    if response is not None and messages:
        response.headers["X-Message-Before"] = encode_message_cursor(messages[0].created_at, messages[0].id)
        response.headers["X-Message-After"] = encode_message_cursor(messages[-1].created_at, messages[-1].id)

    asyncio.create_task(_send_receipts_for_messages(messages, chat_id, current_user.id, db))
    return [MessageResponse(**msg.to_dict()) for msg in messages]


async def _send_receipts_for_messages(
    messages: list,
    chat_id: str,
    current_user_id: str,
    db: AsyncSession
):
    """Send delivery/read receipts for federated messages."""
    from datetime import datetime
    from decemsg.federation.federation_client import is_federated_user, parse_user_id, get_federation_client
    
    receipts_to_send = []
    
    for message in messages:
        # Only send receipts for messages from federated users
        if is_federated_user(message.sender_id) and not message.is_read:
            message.is_read = True
            message.read_at = datetime.utcnow()
            receipts_to_send.append(message)
    
    if receipts_to_send:
        await db.commit()
        
        # Send receipts to federated servers
        for message in receipts_to_send:
            try:
                client = get_federation_client()
                username, domain = parse_user_id(message.sender_id)
                
                if domain:
                    receipt = {
                        "message_id": message.id,
                        "chat_id": chat_id,
                        "status": "read",
                        "user_id": current_user_id,
                        "timestamp": datetime.utcnow().isoformat()
                    }
                    
                    server_info = await client.discover_server(domain)
                    if server_info:
                        import httpx
                        async with httpx.AsyncClient(timeout=10.0) as http_client:
                            try:
                                await http_client.post(
                                    f"{server_info.api_url}/federation/receipts",
                                    json=receipt,
                                    headers={"Content-Type": "application/json"}
                                )
                            except Exception:
                                pass
            except Exception as e:
                print(f"Error sending read receipt: {e}")


@router.post("/chats/{chat_id}/messages", response_model=MessageResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(get_api_rate_limit())
async def send_message(
    request: Request,
    chat_id: str,
    message_data: MessageCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Send a message to a chat."""
    # Verify user is a member of the chat
    result = await db.execute(
        select(Chat)
        .options(selectinload(Chat.members))
        .where(Chat.id == chat_id)
    )
    chat = result.scalar_one_or_none()
    
    if not chat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat not found"
        )
    
    is_member = any(m.user_id == current_user.id for m in chat.members)
    if not is_member:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not a member of this chat"
        )
    
    if not message_data.encrypted_content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="E2EE ciphertext is required for message creation",
        )

    if message_data.message_type != MessageType.TEXT:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only encrypted text messages are currently supported",
        )

    # The server persists and broadcasts only the opaque encrypted event.
    message = Message(
        chat_id=chat_id,
        sender_id=current_user.id,
        content=message_data.encrypted_content,
        message_type=message_data.message_type,
        reply_to_id=message_data.reply_to_id,
    )
    
    db.add(message)
    await db.flush()
    
    # Build the federation outbox entries in the same transaction as the message.
    result = await db.execute(
        select(Message)
        .options(selectinload(Message.reactions), selectinload(Message.sender))
        .where(Message.id == message.id)
    )
    message = result.scalar_one()
    
    # Prepare the response payload; the transaction remains open until the
    # federated outbox entries have been added.
    message_dict = message.to_dict()

    broadcast_message = {
        "type": "new_message",
        "chat_id": chat_id,
        "message": message_dict
    }
    
    # Route to federated members by adding durable outbox jobs before commit.
    for member in chat.members:
        if member.user_id != current_user.id and is_federated_user(member.user_id):
            from_username, from_domain = parse_user_id(current_user.id)
            to_username, to_domain = parse_user_id(member.user_id)

            from decemsg.federation.federation_client import route_message
            result = await route_message(
                from_user=current_user.id,
                to_user=member.user_id,
                content=message_data.encrypted_content,
                message_type=message_data.message_type.value,
                conversation_id=chat_id,
                db=db,
            )
            if result:
                logger.info(
                    f"Federated message queued from {from_username}@{from_domain} "
                    f"to {to_username}@{to_domain}"
                )

    await db.commit()

    # Broadcast only after the message and outbox transaction is durable.
    await manager.broadcast_to_chat(
        broadcast_message, chat_id, exclude_user=current_user.id
    )
    
    # Also send to sender for confirmation
    await manager.send_personal_message(broadcast_message, current_user.id)
    
    return MessageResponse(**message_dict)


@router.post("/messages/{message_id}/reactions", response_model=dict)
async def add_reaction(
    message_id: str,
    reaction_data: ReactionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Add a reaction to a message."""
    result = await db.execute(
        select(Message)
        .options(selectinload(Message.reactions), selectinload(Message.chat).selectinload(Chat.members))
        .where(Message.id == message_id)
    )
    message = result.scalar_one_or_none()
    
    if not message:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found"
        )
    
    # Check if user is a member of the chat
    is_member = any(m.user_id == current_user.id for m in message.chat.members)
    if not is_member:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not a member of this chat"
        )
    
    # Check if user already reacted with this emoji
    existing = next(
        (r for r in message.reactions if r.user_id == current_user.id and r.emoji == reaction_data.emoji),
        None
    )
    
    if existing:
        return {"message": "Reaction already exists", "emoji": reaction_data.emoji}
    
    # Create reaction
    reaction = MessageReaction(
        message_id=message_id,
        user_id=current_user.id,
        emoji=reaction_data.emoji
    )
    db.add(reaction)
    await db.commit()
    
    # Broadcast reaction update
    reaction_update = {
        "type": "reaction_update",
        "chat_id": message.chat_id,
        "message_id": message_id,
        "emoji": reaction_data.emoji,
        "user_id": current_user.id,
        "action": "add"
    }
    await manager.broadcast_to_chat(reaction_update, message.chat_id)
    
    return {"message": "Reaction added", "emoji": reaction_data.emoji}


@router.delete("/messages/{message_id}/reactions/{emoji}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_reaction(
    message_id: str,
    emoji: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Remove a reaction from a message."""
    result = await db.execute(
        select(Message)
        .options(selectinload(Message.reactions), selectinload(Message.chat).selectinload(Chat.members))
        .where(Message.id == message_id)
    )
    message = result.scalar_one_or_none()
    
    if not message:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found"
        )
    
    # Find and remove reaction
    reaction = next(
        (r for r in message.reactions if r.user_id == current_user.id and r.emoji == emoji),
        None
    )
    
    if reaction:
        await db.delete(reaction)
        await db.commit()
        
        # Broadcast reaction update
        reaction_update = {
            "type": "reaction_update",
            "chat_id": message.chat_id,
            "message_id": message_id,
            "emoji": emoji,
            "user_id": current_user.id,
            "action": "remove"
        }
        await manager.broadcast_to_chat(reaction_update, message.chat_id)


# File Upload/Download endpoints
@router.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Upload a file."""
    config = get_config()
    
    # Read file content
    file_data = await file.read()
    filename = file.filename or "unknown"
    
    # Validate file type
    ext = os.path.splitext(filename)[1].lower()
    if ext not in config.messaging.allowed_file_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File type not allowed. Allowed: {config.messaging.allowed_file_types}"
        )
    
    # Validate file size
    max_size = config.messaging.max_file_size_mb * 1024 * 1024
    if len(file_data) > max_size:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File too large. Max size: {config.messaging.max_file_size_mb}MB"
        )
    
    # Generate unique filename
    unique_filename = f"{uuid.uuid4()}{ext}"
    upload_dir = "./data/uploads"
    os.makedirs(upload_dir, exist_ok=True)
    
    file_path = os.path.join(upload_dir, unique_filename)
    
    # Save file
    with open(file_path, "wb") as f:
        f.write(file_data)
    
    # Determine message type
    message_type = MessageType.IMAGE if ext in [".jpg", ".jpeg", ".png", ".gif"] else MessageType.FILE
    
    return {
        "file_url": f"/api/files/{unique_filename}",
        "file_name": filename,
        "file_size": len(file_data),
        "message_type": message_type.value
    }


@router.get("/files/{filename}")
async def download_file(
    filename: str,
    current_user: User = Depends(get_current_user)
):
    """Download a file."""
    file_path = f"./data/uploads/{filename}"
    
    if not os.path.exists(file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found"
        )
    
    # Determine content type
    content_type, _ = mimetypes.guess_type(file_path)
    content_type = content_type or "application/octet-stream"
    
    return FileResponse(
        file_path,
        media_type=content_type,
        filename=filename
    )
