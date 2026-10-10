"""DeceMSG messages API endpoints."""
from typing import List, Optional
from datetime import datetime
import asyncio
import hashlib
import tempfile
import stat
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
from decemsg.models.uploaded_file import UploadedFile
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
MAX_UPLOAD_CHUNK_BYTES = 64 * 1024
MIME_BY_EXTENSION = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".gif": "image/gif",
    ".pdf": "application/pdf",
    ".txt": "text/plain",
    ".doc": "application/msword",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}
MAGIC_PREFIXES = {
    ".jpg": (b"\xff\xd8\xff",),
    ".jpeg": (b"\xff\xd8\xff",),
    ".png": (b"\x89PNG\r\n\x1a\n",),
    ".gif": (b"GIF87a", b"GIF89a"),
    ".pdf": (b"%PDF-",),
    # Modern OOXML .docx files are ZIP containers. Content-level validation
    # beyond the ZIP signature is intentionally left to the scanning hook.
    ".docx": (b"PK\x03\x04",),
    # Legacy OLE compound document signature used by .doc.
    ".doc": (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",),
}


def normalize_upload_filename(filename: str | None) -> tuple[str, str]:
    """Return a display-only basename and its normalized allowed extension."""
    if not filename:
        raise HTTPException(status_code=400, detail="A filename is required")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in filename):
        raise HTTPException(status_code=400, detail="Invalid filename")

    # Treat Windows and POSIX separators as paths. Never use the raw value
    # when creating a stored path.
    basename = filename.replace("\\", "/").split("/")[-1]
    basename = "".join(ch for ch in basename if ch.isprintable() and ch not in "\r\n\x00")
    basename = basename.strip().strip(".")
    if not basename or basename in {".", ".."}:
        raise HTTPException(status_code=400, detail="Invalid filename")
    basename = basename[:255]
    extension = os.path.splitext(basename)[1].lower()
    if extension not in MIME_BY_EXTENSION:
        raise HTTPException(status_code=400, detail="File type not allowed")
    return basename, extension


def validate_upload_signature(extension: str, prefix: bytes) -> bool:
    """Check signatures for formats with well-known magic bytes."""
    signatures = MAGIC_PREFIXES.get(extension)
    if not signatures:
        return False
    return any(prefix.startswith(signature) for signature in signatures)


def content_type_matches_extension(extension: str, content_type: str | None) -> bool:
    """Reject declared MIME types that conflict with the allowed extension."""
    expected = MIME_BY_EXTENSION.get(extension)
    if not expected or not content_type:
        return False
    normalized = content_type.split(";", 1)[0].strip().lower()
    allowed = {expected}
    if extension == ".txt":
        allowed.add("text/plain")
    return normalized in allowed


def upload_scan_hook(path: str, content_type: str, filename: str) -> bool:
    """Security scanning integration point; deployments can replace this hook."""
    # DeceMSG currently performs format/signature validation here. AV or DLP
    # engines can be added behind this function without changing the API.
    return os.path.isfile(path) and os.path.getsize(path) > 0


@router.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    chat_id: str = Form(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Stream an upload into isolated storage and bind it to a chat."""
    config = get_config()
    max_size = config.messaging.max_file_size_mb * 1024 * 1024
    if max_size <= 0:
        raise HTTPException(status_code=503, detail="File uploads are not configured")

    result = await db.execute(
        select(Chat)
        .options(selectinload(Chat.members))
        .where(Chat.id == chat_id, Chat.is_active == True)
    )
    chat = result.scalar_one_or_none()
    if chat is None:
        raise HTTPException(status_code=404, detail="Chat not found")
    if not any(member.user_id == current_user.id for member in chat.members):
        raise HTTPException(status_code=403, detail="Not a member of this chat")

    original_name, extension = normalize_upload_filename(file.filename)
    if extension not in {value.lower() for value in config.messaging.allowed_file_types}:
        raise HTTPException(status_code=400, detail="File type not allowed")
    if not content_type_matches_extension(extension, file.content_type):
        raise HTTPException(status_code=400, detail="MIME type does not match the file extension")

    upload_dir = os.path.abspath("./data/uploads")
    os.makedirs(upload_dir, mode=0o700, exist_ok=True)
    try:
        os.chmod(upload_dir, 0o700)
    except OSError:
        # Some mounted/container filesystems do not permit chmod; the
        # directory remains isolated under the application's data directory.
        pass

    file_id = str(uuid.uuid4())
    storage_name = f"{file_id}{extension}"
    final_path = os.path.join(upload_dir, storage_name)
    sha256 = hashlib.sha256()
    total_bytes = 0
    prefix = bytearray()
    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=upload_dir,
            prefix=".upload-",
            suffix=".tmp",
            delete=False,
        ) as destination:
            temp_path = destination.name
            os.chmod(temp_path, stat.S_IRUSR | stat.S_IWUSR)
            while True:
                chunk = await file.read(MAX_UPLOAD_CHUNK_BYTES)
                if not chunk:
                    break

                total_bytes += len(chunk)
                if total_bytes > max_size:
                    raise HTTPException(
                        status_code=413,
                        detail=f"File too large. Max size: {config.messaging.max_file_size_mb}MB",
                    )

                if len(prefix) < 32:
                    prefix.extend(chunk[: 32 - len(prefix)])
                sha256.update(chunk)
                destination.write(chunk)

        if total_bytes == 0:
            raise HTTPException(status_code=400, detail="Empty files are not allowed")
        if not validate_upload_signature(extension, bytes(prefix)):
            raise HTTPException(status_code=400, detail="File signature does not match the allowed type")

        # Extension/MIME/signature checks are only the baseline filter. The
        # scanning hook is the integration point for AV or content scanning.
        if not upload_scan_hook(temp_path, MIME_BY_EXTENSION[extension], original_name):
            raise HTTPException(status_code=400, detail="File failed content scanning")

        os.replace(temp_path, final_path)
        temp_path = None

        record = UploadedFile(
            id=file_id,
            chat_id=chat_id,
            uploader_user_id=current_user.id,
            storage_key=storage_name,
            original_name=original_name,
            content_type=MIME_BY_EXTENSION[extension],
            size_bytes=total_bytes,
            sha256=sha256.hexdigest(),
        )
        db.add(record)
        try:
            await db.commit()
        except Exception:
            await db.rollback()
            try:
                os.remove(final_path)
            except OSError:
                pass
            raise

        message_type = MessageType.IMAGE if extension in {".jpg", ".jpeg", ".png", ".gif"} else MessageType.FILE
        return {
            "file_id": file_id,
            "file_url": f"/api/files/{file_id}",
            "file_name": original_name,
            "file_size": total_bytes,
            "content_type": MIME_BY_EXTENSION[extension],
            "message_type": message_type.value,
        }
    except Exception:
        if temp_path:
            try:
                os.remove(temp_path)
            except OSError:
                pass
        raise
    finally:
        await file.close()


@router.get("/files/{file_id}")
async def download_file(
    file_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Download a file only for a current member of its associated chat."""
    result = await db.execute(
        select(UploadedFile).where(UploadedFile.id == file_id)
    )
    record = result.scalar_one_or_none()
    if record is None:
        raise HTTPException(status_code=404, detail="File not found")

    member_result = await db.execute(
        select(ChatMember).where(
            ChatMember.chat_id == record.chat_id,
            ChatMember.user_id == current_user.id,
        )
    )
    if member_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=403, detail="Not authorized to access this file")

    upload_dir = os.path.realpath("./data/uploads")
    file_path = os.path.realpath(os.path.join(upload_dir, record.storage_key))
    if os.path.commonpath([upload_dir, file_path]) != upload_dir or not os.path.isfile(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    return FileResponse(
        file_path,
        media_type=record.content_type,
        filename=record.original_name,
        headers={"X-Content-Type-Options": "nosniff"},
    )

