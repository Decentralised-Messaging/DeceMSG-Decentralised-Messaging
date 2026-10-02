"""Federation API endpoints for DeceMSG."""
from typing import Optional, List
from datetime import datetime

from fastapi import APIRouter, HTTPException, Depends, status, Header
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from decemsg.core.database import get_db
from decemsg.core.config import get_config
from decemsg.federation.discovery import get_federation_client, ServerInfo
from decemsg.federation.auth_middleware import AuthResult, require_federation_auth
from decemsg.models.user import User
from decemsg.models.message import Message
from decemsg.models.chat import Chat, ChatMember
from decemsg.models.federated_identity import FederatedIdentity
from sqlalchemy import select
from sqlalchemy.orm import selectinload

router = APIRouter(prefix="/federation", tags=["Federation"])





async def _get_or_create_federated_identity(
    db: AsyncSession,
    address: str,
) -> FederatedIdentity:
    """Resolve a canonical remote address to a dedicated remote identity."""
    if "#" not in address:
        raise HTTPException(status_code=400, detail="Invalid federated identity")
    username, domain = address.split("#", 1)
    result = await db.execute(
        select(FederatedIdentity).where(
            FederatedIdentity.username == username,
            FederatedIdentity.domain == domain,
        )
    )
    identity = result.scalar_one_or_none()
    if identity is None:
        identity = FederatedIdentity(username=username, domain=domain)
        db.add(identity)
        await db.flush()
    identity.last_seen_at = datetime.utcnow()
    return identity


def _origin_actor(user_id: str, origin_domain: str) -> bool:
    """Return true only for a remote actor owned by the authenticated domain."""
    if "#" not in user_id:
        return False
    username, domain = user_id.split("#", 1)
    return bool(username and domain == origin_domain)


def _assert_origin_domain(claimed_domain: str, auth: AuthResult) -> None:
    if claimed_domain != auth.server_domain:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Federation actor is not owned by the authenticated server",
        )


# Request/Response Models
class FederationUserLookup(BaseModel):
    """Response for user lookup."""
    username: str
    display_name: str
    domain: str
    avatar_url: Optional[str] = None
    public_key: Optional[str] = None


class IncomingMessage(BaseModel):
    """Incoming federated message."""
    from_user: str
    from_domain: str
    to_user: str
    content: str
    message_type: str = "text"
    encrypted: bool = False
    encryption_data: Optional[dict] = None


class OutgoingMessage(BaseModel):
    """Outgoing federated message."""
    id: str
    from_user: str
    from_domain: str
    to_user: str
    to_domain: str
    content: str
    message_type: str
    created_at: str


class PresenceUpdate(BaseModel):
    """Presence update from federated server."""
    user: str
    domain: str
    is_online: bool


class KeyExchangeRequest(BaseModel):
    """Request for public key exchange."""
    public_key: str


class KeyExchangeResponse(BaseModel):
    """Response containing user's public key."""
    user_id: str
    public_key: str


# NodeInfo endpoint for server discovery
@router.get("/.well-known/nodeinfo")
async def get_nodeinfo():
    """Return NodeInfo for server discovery."""
    config = get_config()
    return {
        "name": config.server.title,
        "version": "0.1.0",
        "protocols": ["activitypub", "simple-federation"],
        "software": {
            "name": "decemsg",
            "version": "0.1.0"
        },
        "usage": {
            "users": {"total": 0, "activeMonth": 0, "activeWeek": 0}
        }
    }


@router.get("/.well-known/host-meta")
async def get_host_meta():
    """Return XRD/HostMeta for WebFinger discovery."""
    config = get_config()
    return {
        "Subject": config.server.domain,
        "Links": [
            {
                "rel": "lrdd",
                "type": "application/xrd+xml",
                "template": f"https://{config.server.domain}/.well-known/webfinger?resource={{uri}}"
            }
        ]
    }


@router.get("/.well-known/webfinger")
async def webfinger(
    resource: str,
    rel: str = "acct"
):
    """WebFinger endpoint for user discovery."""
    config = get_config()
    
    # Parse the resource (e.g., user@example.com)
    if not resource.startswith("acct:"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid resource format"
        )
    
    account = resource[5:]  # Remove "acct:"
    parts = account.split("@")
    
    if len(parts) != 2:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid account format"
        )
    
    username, domain = parts
    
    # Only respond to requests for this domain
    if domain != config.server.domain:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found on this server"
        )
    
    # Look up user
    return {
        "subject": resource,
        "aliases": [
            f"https://{domain}/users/{username}",
            f"https://{domain}/@{username}"
        ],
        "links": [
            {
                "rel": "http://webfinger.net/rel/profile-page",
                "type": "text/html",
                "href": f"https://{domain}/users/{username}"
            },
            {
                "rel": "self",
                "type": "application/activity+json",
                "href": f"https://{domain}/users/{username}"
            }
        ]
    }


@router.get("/users/{username}", response_model=FederationUserLookup)
async def get_federated_user(
    username: str,
    db: AsyncSession = Depends(get_db)
):
    """Get user information for federation, including public key for E2EE."""
    config = get_config()
    
    # Look up user
    result = await db.execute(
        select(User).where(
            User.username == username,
            User.domain == config.server.domain,
            User.is_active == True
        )
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Get user's public key for E2EE
    from decemsg.federation.encryption import get_user_key_pair
    public_key = None
    key_pair = get_user_key_pair(user.id)
    if key_pair:
        public_key = key_pair.public_key
    
    return FederationUserLookup(
        username=user.username,
        display_name=user.display_name,
        domain=user.domain,
        avatar_url=user.avatar_url,
        public_key=public_key
    )


@router.post("/keys/{username}")
async def exchange_public_key(
    username: str,
    key_data: KeyExchangeRequest,
    db: AsyncSession = Depends(get_db)
):
    """Exchange public keys with a federated user for E2EE.
    
    This endpoint allows a remote server to provide a user's public key
    that will be cached for encrypting outgoing messages to that user.
    """
    config = get_config()
    
    # Look up local user
    result = await db.execute(
        select(User).where(
            User.username == username,
            User.domain == config.server.domain,
            User.is_active == True
        )
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Cache the public key with the federated user ID
    federated_user_id = f"{username}#{config.server.domain}"
    from decemsg.federation.encryption import cache_federated_key
    cache_federated_key(federated_user_id, key_data.public_key)
    
    # Return our public key if we have one
    from decemsg.federation.encryption import get_user_key_pair
    response_key = None
    key_pair = get_user_key_pair(user.id)
    if key_pair:
        response_key = key_pair.public_key
    
    return KeyExchangeResponse(
        user_id=user.id,
        public_key=response_key or ""
    )


@router.get("/keys/{username}")
async def get_public_key(
    username: str,
    db: AsyncSession = Depends(get_db)
):
    """Get a user's public key for E2EE."""
    config = get_config()
    
    # Look up user
    result = await db.execute(
        select(User).where(
            User.username == username,
            User.domain == config.server.domain,
            User.is_active == True
        )
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Get user's public key
    from decemsg.federation.encryption import get_user_key_pair
    key_pair = get_user_key_pair(user.id)
    
    return {
        "user_id": user.id,
        "public_key": key_pair.public_key if key_pair else None
    }


@router.post("/messages")
async def receive_message(
    message: IncomingMessage,
    db: AsyncSession = Depends(get_db),
    federation_auth: AuthResult = Depends(require_federation_auth),
):
    """Receive a message from a federated server.
    
    This endpoint:
    1. Finds the local recipient user
    2. Creates or finds a direct chat with the federated sender
    3. Stores the message in the proper chat
    4. Triggers WebSocket notification to the recipient
    """
    config = get_config()
    _assert_origin_domain(message.from_domain, federation_auth)
    
    # Find the recipient user
    result = await db.execute(
        select(User).where(
            User.username == message.to_user,
            User.domain == config.server.domain
        )
    )
    recipient = result.scalar_one_or_none()
    
    if not recipient:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recipient not found"
        )
    
    # Resolve the remote actor to an explicit FederatedIdentity.
    federated_sender_id = f"{message.from_user}#{message.from_domain}"
    federated_identity = await _get_or_create_federated_identity(db, federated_sender_id)
    
    # Find or create direct chat with federated user
    # Chat ID is derived from sorted user IDs to ensure consistency
    import uuid
    if recipient.id < federated_sender_id:
        chat_id = f"fed_{uuid.uuid5(uuid.NAMESPACE_DNS, f'{recipient.id}:{federated_sender_id}')}"
    else:
        chat_id = f"fed_{uuid.uuid5(uuid.NAMESPACE_DNS, f'{federated_sender_id}:{recipient.id}')}"
    
    # Check if chat exists
    result = await db.execute(
        select(Chat).where(Chat.id == chat_id)
    )
    chat = result.scalar_one_or_none()
    
    if not chat:
        # Create new federated direct chat
        chat = Chat(
            id=chat_id,
            type="direct",
            name=None,
            is_active=True,
            keep_history=True
        )
        db.add(chat)
        await db.flush()
        
        # Add local user as member
        local_member = ChatMember(
            chat_id=chat_id,
            user_id=recipient.id,
            role="member"
        )
        db.add(local_member)
        
        # Add federated user as member
        fed_member = ChatMember(
            chat_id=chat_id,
            federated_identity_id=federated_identity.id,
            role="member",
        )
        db.add(fed_member)
    
    # Create the message in the proper chat
    new_message = Message(
        chat_id=chat_id,
        sender_federated_identity_id=federated_identity.id,
        content=message.content,
        message_type=message.message_type,
        is_deleted=False
    )
    db.add(new_message)
    await db.commit()
    await db.refresh(new_message)
    
    # Notify recipient via WebSocket
    try:
        from decemsg.api.websocket import manager
        import asyncio
        asyncio.create_task(
            _notify_recipient(manager, recipient.id, chat_id, new_message)
        )
    except Exception as e:
        print(f"WebSocket notification failed: {e}")
    
    return {
        "status": "received",
        "message_id": str(new_message.id),
        "chat_id": chat_id
    }


async def _notify_recipient(manager, user_id: str, chat_id: str, message):
    """Notify recipient via WebSocket about new federated message."""
    from decemsg.api.schemas import MessageResponse
    from decemsg.api.websocket import ConnectionManager
    
    # Get sender info
    from decemsg.core.database import get_db
    async for db in get_db():
        from sqlalchemy import select
        if message.sender_federated_identity_id:
            result = await db.execute(
                select(FederatedIdentity).where(
                    FederatedIdentity.id == message.sender_federated_identity_id
                )
            )
            remote = result.scalar_one_or_none()
            sender_reference = remote.full_address if remote else message.sender_federated_identity_id
            sender_info = {
                "id": sender_reference,
                "username": remote.username if remote else "unknown",
                "display_name": remote.display_name if remote else "Unknown",
                "avatar_url": remote.avatar_url if remote else None,
                "domain": remote.domain if remote else None,
            }
        else:
            sender_id = message.sender_id
            result = await db.execute(
                select(User).where(User.id == sender_id)
            )
            user = result.scalar_one_or_none()
            if user:
                sender_info = {
                    "id": user.id,
                    "username": user.username,
                    "display_name": user.display_name,
                    "avatar_url": user.avatar_url,
                    "domain": user.domain
                }
            else:
                sender_info = {"id": sender_id, "username": "unknown", "display_name": "Unknown"}
        break
    
    # Build message notification
    notification = {
        "type": "new_message",
        "chat_id": chat_id,
        "message": {
            "id": str(message.id),
            "chat_id": chat_id,
            "sender_id": sender_reference if message.sender_federated_identity_id else message.sender_id,
            "content": message.content,
            "message_type": message.message_type,
            "created_at": message.created_at.isoformat() if hasattr(message, 'created_at') else str(message.created_at),
            "is_deleted": False,
            "sender": sender_info,
            "reactions": {}
        }
    }
    
    # Send to recipient
    await manager.send_personal_message(notification, user_id)


@router.post("/presence")
async def receive_presence(
    presence: PresenceUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Receive presence update from federated server."""
    # In production, you'd update local presence cache
    # For now, just acknowledge
    return {"status": "ok"}


# Internal API for local federation
@router.get("/servers")
async def list_federated_servers():
    """List all known federated servers."""
    client = get_federation_client()
    servers = await client.discover_all_known_servers()
    return {"servers": [s.dict() for s in servers]}


@router.post("/servers/discover")
async def discover_server(
    domain: str,
):
    """Discover a new federated server."""
    client = get_federation_client()
    server_info = await client.discover_server(domain)
    
    if server_info:
        return {"status": "discovered", "server": server_info.dict()}
    return {"status": "failed", "message": "Could not discover server"}


@router.post("/servers/register")
async def register_server(
    domain: str,
    api_url: str,
    name: str = None,
):
    """Manually register a federated server (for testing)."""
    from decemsg.federation.discovery import ServerInfo
    client = get_federation_client()
    server_info = ServerInfo(
        domain=domain,
        name=name or domain,
        api_url=api_url,
        version="1.0.0",
    )
    client.registry.add_server(domain, server_info)
    return {"status": "registered", "server": server_info.dict()}


@router.get("/lookup/{username}@{domain}")
async def lookup_remote_user(
    username: str,
    domain: str,
):
    """Look up a user on a remote federated server."""
    client = get_federation_client()
    user_info = await client.lookup_user(username, domain)
    
    if user_info:
        return {"status": "found", "user": user_info}
    return {"status": "not_found", "message": "User not found on remote server"}


@router.post("/send")
async def send_federated_message(
    from_user: str,
    from_domain: str,
    to_user: str,
    to_domain: str,
    content: str,
    message_type: str = "text"
):
    """Send a message to a federated user."""
    client = get_federation_client()
    success = await client.send_message(
        from_user, from_domain,
        to_user, to_domain,
        content, message_type
    )
    
    if success:
        return {"status": "sent"}
    return {"status": "failed", "message": "Could not send message"}


class ChatSyncRequest(BaseModel):
    """Request to sync chat membership from federated server."""
    chat_id: str
    members: list[str]


class DeliveryReceipt(BaseModel):
    """Delivery receipt for a message."""
    message_id: str
    chat_id: str
    status: str  # "delivered" or "read"
    user_id: str
    timestamp: str


class ReceiptRequest(BaseModel):
    """Request to update message receipt status."""
    message_id: str
    chat_id: str
    status: str  # "delivered" or "read"


class GroupChatSyncRequest(BaseModel):
    """Request to sync group chat from federated server."""
    chat_id: str
    name: str
    members: list[str]
    created_by: str


class MessageUpdateRequest(BaseModel):
    """Request to update a message (edit)."""
    message_id: str
    chat_id: str
    content: str


class MessageDeleteRequest(BaseModel):
    """Request to delete a message."""
    message_id: str
    chat_id: str


class TypingIndicatorRequest(BaseModel):
    """Typing indicator from federated user."""
    chat_id: str
    user_id: str
    is_typing: bool


class BlockSyncRequest(BaseModel):
    """Request to sync block list with federated server."""
    blocked_user: str
    blocked_domain: str
    action: str  # "block" or "unblock"


class ProfileUpdateRequest(BaseModel):
    """Profile update from federated user."""
    user_id: str
    display_name: Optional[str] = None
    avatar_url: Optional[str] = None


class FileMetadata(BaseModel):
    """File metadata for federation."""
    filename: str
    mime_type: str
    size: int
    checksum: str
    uploaded_by: str


class FederatedFileResponse(BaseModel):
    """Response for federated file upload."""
    file_id: str
    url: str


class DisappearingTimerRequest(BaseModel):
    """Request to set disappearing timer."""
    chat_id: str
    duration_seconds: int


class SearchRequest(BaseModel):
    """Search request across federated servers."""
    query: str
    user_id: str
    limit: int = 50


@router.post("/chats/sync")
async def sync_chat_from_federation(
    sync_data: ChatSyncRequest,
    db: AsyncSession = Depends(get_db),
    federation_auth: AuthResult = Depends(require_federation_auth),
):
    """Synchronize an existing direct chat without granting local-user authority."""
    remote_members = [
        member for member in sync_data.members
        if "#" in member
    ]
    if not remote_members or not all(
        _origin_actor(member, federation_auth.server_domain)
        for member in remote_members
    ):
        raise HTTPException(status_code=403, detail="Invalid federation member authority")

    result = await db.execute(select(Chat).where(Chat.id == sync_data.chat_id))
    chat = result.scalar_one_or_none()
    if not chat or chat.type.value != "direct":
        raise HTTPException(status_code=403, detail="Federation cannot create or replace local chat state")

    existing_result = await db.execute(
        select(ChatMember).where(ChatMember.chat_id == sync_data.chat_id)
    )
    existing_ids = {member.user_id for member in existing_result.scalars().all()}

    for member_id in sync_data.members:
        if "#" in member_id:
            if not _origin_actor(member_id, federation_auth.server_domain):
                raise HTTPException(status_code=403, detail="Remote member belongs to another domain")
            if member_id not in existing_ids:
                db.add(ChatMember(
                    chat_id=sync_data.chat_id,
                    user_id=member_id,
                    role="member",
                ))
        elif member_id not in existing_ids:
            raise HTTPException(status_code=403, detail="Remote server cannot add local users")

    await db.commit()
    return {"status": "synced", "chat_id": sync_data.chat_id}


@router.post("/chats/group/sync")
async def sync_group_chat(
    group_data: GroupChatSyncRequest,
    db: AsyncSession = Depends(get_db),
    federation_auth: AuthResult = Depends(require_federation_auth),
):
    """Synchronize an existing group with server-owned remote members."""
    if not _origin_actor(group_data.created_by, federation_auth.server_domain):
        raise HTTPException(status_code=403, detail="Group creator is not owned by authenticated server")

    result = await db.execute(select(Chat).where(Chat.id == group_data.chat_id))
    chat = result.scalar_one_or_none()
    if not chat or chat.type.value != "group":
        raise HTTPException(status_code=403, detail="Federation cannot create or replace local group state")

    existing_result = await db.execute(
        select(ChatMember).where(ChatMember.chat_id == group_data.chat_id)
    )
    existing_ids = {member.user_id for member in existing_result.scalars().all()}

    for member_id in group_data.members:
        if "#" in member_id:
            if not _origin_actor(member_id, federation_auth.server_domain):
                raise HTTPException(status_code=403, detail="Remote member belongs to another domain")
            if member_id not in existing_ids:
                db.add(ChatMember(
                    chat_id=group_data.chat_id,
                    user_id=member_id,
                    role="admin" if member_id == group_data.created_by else "member",
                ))
        elif member_id not in existing_ids:
            raise HTTPException(status_code=403, detail="Remote server cannot add local members")

    await db.commit()

    try:
        from decemsg.api.websocket import manager
        import asyncio
        asyncio.create_task(
            _notify_group_update(manager, group_data.chat_id, group_data.members)
        )
    except Exception as e:
        print(f"Group update notification failed: {e}")

    return {"status": "synced", "chat_id": group_data.chat_id}


async def _notify_group_update(manager, chat_id: str, members: list):
    """Notify members about group chat updates."""
    notification = {
        "type": "group_updated",
        "chat_id": chat_id,
        "members": members
    }
    for member_id in members:
        if not is_federated_user(member_id):
            await manager.send_personal_message(notification, member_id)


@router.post("/chats/group/members")
async def update_group_members(
    chat_id: str,
    action: str,
    members: List[str],
    db: AsyncSession = Depends(get_db),
    federation_auth: AuthResult = Depends(require_federation_auth),
):
    """Update group chat members from federated server."""
    config = get_config()
    
    if action not in {"add", "remove"}:
        raise HTTPException(status_code=400, detail="Invalid group member action")
    if not members or not all(_origin_actor(member, federation_auth.server_domain) for member in members):
        raise HTTPException(status_code=403, detail="Remote server may only manage its own actors")
    
    # Find the chat
    result = await db.execute(
        select(Chat).where(Chat.id == chat_id)
    )
    chat = result.scalar_one_or_none()
    
    if not chat or chat.type.value != "group":
        raise HTTPException(status_code=404, detail="Group chat not found")
    
    for member_id in members:
        if action == "add":
            # Check if member exists
            existing = await db.execute(
                select(ChatMember).where(
                    ChatMember.chat_id == chat_id,
                    ChatMember.user_id == member_id
                )
            )
            if not existing.scalar_one_or_none():
                member = ChatMember(
                    chat_id=chat_id,
                    user_id=member_id,
                    role="member"
                )
                db.add(member)
        elif action == "remove":
            existing = await db.execute(
                select(ChatMember).where(
                    ChatMember.chat_id == chat_id,
                    ChatMember.user_id == member_id
                )
            )
            member = existing.scalar_one_or_none()
            if member:
                await db.delete(member)
    
    await db.commit()
    
    # Notify remaining members
    try:
        from decemsg.api.websocket import manager
        import asyncio
        notification = {
            "type": "group_members_updated",
            "chat_id": chat_id,
            "action": action,
            "members": members
        }
        for member_id in members:
            if not is_federated_user(member_id):
                await manager.send_personal_message(notification, member_id)
    except Exception as e:
        print(f"Member update notification failed: {e}")
    
    return {"status": "updated", "chat_id": chat_id}


@router.post("/receipts")
async def receive_delivery_receipt(
    receipt: DeliveryReceipt,
    db: AsyncSession = Depends(get_db),
    federation_auth: AuthResult = Depends(require_federation_auth),
):
    """Receive a receipt only from the server owning the recipient actor."""
    if not _origin_actor(receipt.user_id, federation_auth.server_domain):
        raise HTTPException(status_code=403, detail="Receipt actor is not owned by authenticated server")
    if receipt.status not in {"delivered", "read"}:
        raise HTTPException(status_code=400, detail="Invalid receipt status")

    result = await db.execute(select(Message).where(Message.id == receipt.message_id))
    message = result.scalar_one_or_none()
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    if message.chat_id != receipt.chat_id:
        raise HTTPException(status_code=403, detail="Receipt chat does not match message")
    if "#" in (message.sender_id or ""):
        raise HTTPException(status_code=403, detail="Receipt target is not a local sender")

    member_result = await db.execute(
        select(ChatMember).where(
            ChatMember.chat_id == receipt.chat_id,
            ChatMember.user_id == receipt.user_id,
        )
    )
    if member_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=403, detail="Receipt actor is not a chat member")

    if receipt.status == "delivered":
        message.is_delivered = True
        message.delivered_at = datetime.now()
    else:
        message.is_read = True
        message.read_at = datetime.now()

    await db.commit()

    try:
        from decemsg.api.websocket import manager
        import asyncio
        asyncio.create_task(_notify_receipt(manager, message.sender_id, receipt))
    except Exception as e:
        print(f"Receipt notification failed: {e}")

    return {"status": "received"}


async def _notify_receipt(manager, sender_id: str, receipt: DeliveryReceipt):
    """Notify sender about message receipt."""
    from datetime import datetime
    
    notification = {
        "type": "message_receipt",
        "message_id": receipt.message_id,
        "chat_id": receipt.chat_id,
        "status": receipt.status,
        "user_id": receipt.user_id,
        "timestamp": receipt.timestamp
    }
    
    await manager.send_personal_message(notification, sender_id)


# Helper to send delivery receipts to federated users
async def send_receipt_to_federated(
    from_user: str,
    message_id: str,
    chat_id: str,
    status: str
) -> bool:
    """Send a delivery receipt to a federated sender.
    
    Args:
        from_user: The local user who is sending the receipt
        message_id: The message ID being acknowledged
        chat_id: The chat containing the message
        status: "delivered" or "read"
    
    Returns:
        True if receipt was sent successfully
    """
    from decemsg.federation.federation_client import parse_user_id, get_federation_client
    from datetime import datetime
    
    username, domain = parse_user_id(from_user)
    
    # Don't send to local users
    config = get_config()
    if domain == config.server.domain or domain is None:
        return False
    
    try:
        client = get_federation_client()
        server_info = await client.discover_server(domain)
        
        if not server_info:
            return False
        
        receipt = DeliveryReceipt(
            message_id=message_id,
            chat_id=chat_id,
            status=status,
            user_id=from_user,
            timestamp=datetime.now().isoformat()
        )
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{server_info.api_url}/federation/receipts",
                json=receipt.model_dump(),
                headers={"Content-Type": "application/json"}
            )
            
            return response.status_code in (200, 201, 202)
            
    except Exception as e:
        print(f"Failed to send receipt: {e}")
        return False


# ============= Message Edit/Delete Sync =============

@router.post("/messages/update")
async def receive_message_update(
    update: MessageUpdateRequest,
    db: AsyncSession = Depends(get_db),
    federation_auth: AuthResult = Depends(require_federation_auth),
):
    """Receive an edit only from the server that owns the message actor."""
    result = await db.execute(select(Message).where(Message.id == update.message_id))
    message = result.scalar_one_or_none()
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    if (
        message.chat_id != update.chat_id
        or not _origin_actor(message.sender_id or "", federation_auth.server_domain)
    ):
        raise HTTPException(status_code=403, detail="Federation server is not message origin")

    message.content = update.content
    await db.commit()

    try:
        from decemsg.api.websocket import manager
        import asyncio
        asyncio.create_task(
            _notify_message_update(manager, update.chat_id, update.message_id, update.content)
        )
    except Exception as e:
        print(f"Message update notification failed: {e}")

    return {"status": "updated"}


async def _notify_message_update(manager, chat_id: str, message_id: str, content: str):
    """Notify members about message edit."""
    notification = {
        "type": "message_updated",
        "chat_id": chat_id,
        "message_id": message_id,
        "content": content
    }
    await manager.broadcast_to_chat(notification, chat_id)


@router.post("/messages/delete")
async def receive_message_delete(
    delete: MessageDeleteRequest,
    db: AsyncSession = Depends(get_db),
    federation_auth: AuthResult = Depends(require_federation_auth),
):
    """Receive a delete only from the server that owns the message actor."""
    result = await db.execute(select(Message).where(Message.id == delete.message_id))
    message = result.scalar_one_or_none()
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    if (
        message.chat_id != delete.chat_id
        or not _origin_actor(message.sender_id or "", federation_auth.server_domain)
    ):
        raise HTTPException(status_code=403, detail="Federation server is not message origin")

    message.is_deleted = True
    await db.commit()

    try:
        from decemsg.api.websocket import manager
        import asyncio
        asyncio.create_task(
            _notify_message_delete(manager, delete.chat_id, delete.message_id)
        )
    except Exception as e:
        print(f"Message delete notification failed: {e}")

    return {"status": "deleted"}


async def _notify_message_delete(manager, chat_id: str, message_id: str):
    """Notify members about message deletion."""
    notification = {
        "type": "message_deleted",
        "chat_id": chat_id,
        "message_id": message_id
    }
    await manager.broadcast_to_chat(notification, chat_id)


# ============= Typing Indicators =============

@router.post("/typing")
async def receive_typing_indicator(
    typing: TypingIndicatorRequest,
    db: AsyncSession = Depends(get_db),
    federation_auth: AuthResult = Depends(require_federation_auth),
):
    """Receive a typing indicator only from an authorized remote actor."""
    if not _origin_actor(typing.user_id, federation_auth.server_domain):
        raise HTTPException(status_code=403, detail="Typing actor is not owned by authenticated server")

    result = await db.execute(
        select(ChatMember).where(ChatMember.chat_id == typing.chat_id)
    )
    members = result.scalars().all()
    if not any(member.user_id == typing.user_id for member in members):
        raise HTTPException(status_code=403, detail="Typing actor is not a chat member")

    from decemsg.api.websocket import manager
    for member in members:
        if not is_federated_user(member.user_id):
            await manager.send_personal_message(
                {
                    "type": "typing_indicator",
                    "chat_id": typing.chat_id,
                    "user_id": typing.user_id,
                    "is_typing": typing.is_typing,
                },
                member.user_id,
            )

    return {"status": "received"}


@router.post("/blocks/sync")
async def sync_block_list(
    block_data: BlockSyncRequest,
    db: AsyncSession = Depends(get_db)
):
    """Sync block list with federated server."""
    # In production, this would store the block in a BlockedUser table
    # For now, we just acknowledge the request
    return {"status": "synced"}


@router.get("/blocks/{user_id}")
async def get_block_list(user_id: str):
    """Get block list for a user (returns empty for federated users)."""
    # In production, return actual block list from database
    return {"blocked_users": []}


# ============= Profile Sync =============

@router.post("/profile/update")
async def receive_profile_update(
    profile: ProfileUpdateRequest,
    db: AsyncSession = Depends(get_db)
):
    """Receive a profile update from a federated user."""
    try:
        # Update cached federated user info
        from decemsg.federation.encryption import cache_federated_key
        
        # Store profile update with the federated user ID
        federated_user_id = profile.user_id
        
        # Notify local users who have chats with this federated user
        try:
            from decemsg.api.websocket import manager
            import asyncio
            
            notification = {
                "type": "federated_user_updated",
                "user_id": federated_user_id,
                "display_name": profile.display_name,
                "avatar_url": profile.avatar_url
            }
            
            # Find all local users who have chats with this federated user
            result = await db.execute(
                select(ChatMember).where(ChatMember.user_id == federated_user_id)
            )
            chat_ids = {m.chat_id for m in result.scalars().all()}
            
            for chat_id in chat_ids:
                await manager.broadcast_to_chat(notification, chat_id)
        except Exception as e:
            print(f"Profile update notification failed: {e}")
        
        return {"status": "updated"}
    except Exception as e:
        print(f"Error processing profile update: {e}")
        return {"status": "error"}


# ============= File Federation =============

@router.post("/files")
async def upload_federated_file(
    metadata: FileMetadata,
    db: AsyncSession = Depends(get_db)
):
    """Upload a file from a federated user.
    
    This endpoint receives files uploaded by federated users.
    The actual file content should be sent as multipart form data.
    """
    import uuid
    import hashlib
    
    config = get_config()
    
    # Create a file ID
    file_id = str(uuid.uuid4())
    
    # In a full implementation, we'd save the file to disk
    # For now, we just acknowledge the upload
    return FederatedFileResponse(
        file_id=file_id,
        url=f"/api/files/{file_id}"
    )


@router.get("/files/{file_id}")
async def download_federated_file(
    file_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Download a file for a federated user."""
    # In a full implementation, we'd serve the file
    raise HTTPException(status_code=404, detail="File not found")


@router.get("/files/{file_id}/metadata")
async def get_federated_file_metadata(
    file_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Get metadata for a federated file."""
    # In a full implementation, we'd return actual metadata
    raise HTTPException(status_code=404, detail="File not found")


# ============= Disappearing Messages =============

@router.post("/disappearing/sync")
async def sync_disappearing_timer(
    timer: DisappearingTimerRequest,
    db: AsyncSession = Depends(get_db)
):
    """Sync disappearing message timer from federated server."""
    try:
        from decemsg.federation.disappearing_messages import get_disappearing_manager
        
        manager = get_disappearing_manager()
        manager.set_chat_timer(timer.chat_id, timer.duration_seconds)
        
        return {"status": "synced", "chat_id": timer.chat_id}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ============= Contact Sync =============

@router.post("/contacts/sync")
async def sync_contact(
    action_data: dict,
    db: AsyncSession = Depends(get_db)
):
    """Receive contact sync from federated server."""
    try:
        from decemsg.federation.contacts_sync import get_contact_manager
        
        manager = get_contact_manager()
        
        action = action_data.get("action")
        owner_id = action_data.get("owner_id")
        owner_username = action_data.get("owner_username")
        owner_domain = action_data.get("owner_domain")
        contact_id = action_data.get("contact_id")
        contact_username = action_data.get("contact_username")
        contact_domain = action_data.get("contact_domain")
        
        if action == "add":
            manager.add_contact(
                owner_id=owner_id,
                contact_id=contact_id,
                contact_username=contact_username,
                contact_domain=contact_domain,
                contact_display_name=contact_username,
                is_federated=True
            )
        elif action == "remove":
            manager.remove_contact(owner_id, contact_id)
        elif action == "block":
            manager.update_status(owner_id, contact_id, "blocked")
        elif action == "unblock":
            manager.update_status(owner_id, contact_id, "accepted")
        
        return {"status": "synced"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ============= Push Notifications =============

@router.post("/push/relay")
async def relay_push_notification(
    push_data: dict,
    db: AsyncSession = Depends(get_db)
):
    """Receive push notification relay from federated server."""
    try:
        from decemsg.federation.push_notifications import (
            get_push_relay,
            NotificationPayload,
            send_push_notification
        )
        
        user_id = push_data.get("user_id")
        notification_data = push_data.get("notification", {})
        
        notification = NotificationPayload(
            title=notification_data.get("title", "New message"),
            body=notification_data.get("body", ""),
            icon=notification_data.get("icon"),
            tag=notification_data.get("tag")
        )
        
        # Send to user (local delivery)
        success = await send_push_notification(user_id, notification)
        
        return {"status": "relayed" if success else "failed"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ============= Health & Status =============

@router.get("/health")
async def federation_health():
    """Return health status for federated servers."""
    from decemsg.federation.health_monitor import get_health_monitor
    
    monitor = get_health_monitor()
    health = monitor.get_all_health()
    
    return {
        "status": "ok",
        "servers": [h.to_dict() for h in health]
    }


@router.get("/verify/challenge")
async def get_verification_challenge():
    """Get a domain verification challenge."""
    from decemsg.federation.domain_verification import get_domain_verifier
    
    config = get_config()
    verifier = get_domain_verifier()
    
    challenge_data = verifier.create_challenge(config.server.domain)
    
    return challenge_data


# ============= Search =============

@router.post("/search")
async def federated_search(
    search_req: SearchRequest,
    db: AsyncSession = Depends(get_db)
):
    """Search messages for a federated user."""
    try:
        from decemsg.federation.federated_search import get_search_engine
        
        engine = get_search_engine()
        
        # Search local messages for this user
        results = await engine.search_local(
            query=search_req.query,
            user_id=search_req.user_id,
            limit=search_req.limit
        )
        
        return {
            "results": [r.to_dict() for r in results],
            "server_domain": get_config().server.domain
        }
    except Exception as e:
        return {"error": str(e), "results": []}


# ============= Migration =============

@router.get("/migration/export/{user_id}")
async def export_user_migration(
    user_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Export user data for migration."""
    from decemsg.federation.user_migration import get_migration_manager
    
    manager = get_migration_manager()
    data = manager.export_user_data(user_id)
    
    return data


@router.post("/migration/import")
async def import_user_migration(
    migration_data: dict,
    db: AsyncSession = Depends(get_db)
):
    """Import user data from migration."""
    from decemsg.federation.user_migration import get_migration_manager
    
    manager = get_migration_manager()
    success = manager.import_user_data(migration_data)
    
    return {"status": "success" if success else "failed"}


# ============= ActivityPub Inbox/Outbox =============

@router.post("/inbox")
async def ap_inbox(
    activity: dict,
    db: AsyncSession = Depends(get_db)
):
    """ActivityPub inbox endpoint."""
    from decemsg.federation.activitypub import get_ap_processor
    
    processor = get_ap_processor()
    result = processor.process_activity(activity)
    
    return result


@router.get("/outbox")
async def ap_outbox(
    actor: str = None,
    limit: int = 100
):
    """ActivityPub outbox endpoint."""
    from decemsg.federation.activitypub import get_ap_processor
    
    processor = get_ap_processor()
    activities = processor.outbox.get_outbox(actor, limit)
    
    return {
        "items": [a["activity"] for a in activities],
        "totalItems": len(activities)
    }


@router.post("/outbox")
async def ap_post_outbox(
    activity: dict,
    db: AsyncSession = Depends(get_db)
):
    """Post to ActivityPub outbox."""
    from decemsg.federation.activitypub import get_ap_processor
    
    processor = get_ap_processor()
    activity_id = processor.outbox.post(activity)
    
    return {"id": activity_id, "status": "posted"}


@router.get("/actor")
async def ap_actor():
    """Get the server's ActivityPub actor."""
    from decemsg.federation.activitypub import APPerson
    from decemsg.core.config import get_config
    
    config = get_config()
    
    actor = APPerson(
        id=f"https://{config.server.domain}/federation/actor",
        preferredUsername="server",
        name="DeceMSG Server",
        inbox=f"https://{config.server.domain}/federation/inbox",
        outbox=f"https://{config.server.domain}/federation/outbox"
    )
    
    return actor.to_dict()


# ============= Per-Server Rate Limiting =============

@router.get("/rate-limits")
async def get_rate_limit_status():
    """Get rate limiting status for all servers."""
    from decemsg.federation.rate_limiter import get_rate_limiter
    
    limiter = get_rate_limiter()
    return {
        "status": limiter.get_all_status(),
        "stats": limiter.get_stats()
    }


@router.post("/rate-limits/{domain}")
async def set_rate_limit(
    domain: str,
    limit_data: dict
):
    """Set custom rate limit for a server."""
    from decemsg.federation.rate_limiter import get_rate_limiter, RateLimit
    
    limiter = get_rate_limiter()
    limit = RateLimit(
        requests_per_minute=limit_data.get("requests_per_minute", 60),
        requests_per_hour=limit_data.get("requests_per_hour", 1000),
        requests_per_day=limit_data.get("requests_per_day", 10000),
        burst_limit=limit_data.get("burst_limit", 10)
    )
    limiter.set_limit(domain, limit)
    
    return {"status": "set", "domain": domain}


# ============= Spam Filtering =============

@router.get("/spam/stats")
async def get_spam_stats():
    """Get spam filter statistics."""
    from decemsg.federation.spam_filter import get_spam_filter
    
    filter = get_spam_filter()
    return filter.get_stats()


@router.get("/spam/blocked")
async def get_blocked_domains():
    """Get list of blocked domains."""
    from decemsg.federation.spam_filter import get_spam_filter
    
    filter = get_spam_filter()
    return {"blocked_domains": filter.get_blocked_domains()}


@router.post("/spam/block/{domain}")
async def block_domain(
    domain: str,
    block_data: dict = None
):
    """Block a domain."""
    from decemsg.federation.spam_filter import get_spam_filter
    
    filter = get_spam_filter()
    reason = block_data.get("reason", "Manual block") if block_data else "Manual block"
    filter.block_domain(domain, reason)
    
    return {"status": "blocked", "domain": domain}


@router.delete("/spam/block/{domain}")
async def unblock_domain(domain: str):
    """Unblock a domain."""
    from decemsg.federation.spam_filter import get_spam_filter
    
    filter = get_spam_filter()
    filter.unblock_domain(domain)
    
    return {"status": "unblocked", "domain": domain}


# ============= SRV Records =============

@router.get("/srv/records")
async def get_srv_records():
    """Get SRV records for this server."""
    from decemsg.federation.srv_publisher import get_srv_publisher
    
    publisher = get_srv_publisher()
    return publisher.generate_records()


@router.get("/srv/zone-file")
async def get_zone_file(format: str = "standard"):
    """Get DNS zone file for SRV records."""
    from decemsg.federation.srv_publisher import get_srv_publisher
    
    publisher = get_srv_publisher()
    return {"zone_file": publisher.get_zone_file(format)}


@router.get("/discovery")
async def get_discovery_document():
    """Get server discovery document."""
    from decemsg.federation.srv_publisher import get_srv_publisher
    
    publisher = get_srv_publisher()
    return publisher.get_discovery_document()


# ============= Peers Endpoint =============

@router.get("/peers")
async def get_peers():
    """Get list of federated peers (ActivityPub compatible)."""
    from decemsg.federation.discovery_bootstrap import get_discovery_bootstrap
    from decemsg.federation.health_monitor import get_health_monitor
    from decemsg.core.config import get_config
    
    config = get_config()
    bootstrap = get_discovery_bootstrap()
    monitor = get_health_monitor()
    
    servers = bootstrap.get_known_servers()
    
    peers = []
    for server in servers:
        domain = server["domain"]
        if domain == config.server.domain:
            continue
        
        health = monitor.get_health(domain)
        peers.append({
            "id": f"https://{domain}",
            "name": domain,
            "type": "Peer",
            "domain": domain,
            "api_url": server["api_url"],
            "is_online": health.is_online if health else False,
            "uptime": health.uptime_percentage if health else 0
        })
    
    return {
        "type": "OrderedCollection",
        "id": f"https://{config.server.domain}/federation/peers",
        "totalItems": len(peers),
        "items": peers
    }
