"""DeceMSG chats API endpoints."""
from typing import List, Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_
from sqlalchemy.orm import selectinload

from decemsg.core.database import get_db
from decemsg.core.auth import get_current_user
from decemsg.core.config import get_config
from decemsg.core.websocket import manager
from decemsg.models.user import User
from decemsg.models.chat import Chat, ChatMember, ChatType, MemberRole
from decemsg.federation.federation_client import is_federated_user, get_user_domain, parse_user_id

router = APIRouter(prefix="/api/chats", tags=["Chats"])


# Request/Response Models
class ChatCreate(BaseModel):
    """Chat creation request."""
    type: ChatType = ChatType.DIRECT
    name: str | None = Field(None, max_length=100)
    member_ids: List[str] = []
    keep_history: bool | None = None


class ChatUpdate(BaseModel):
    """Chat update request."""
    name: str | None = None
    avatar_url: str | None = None
    keep_history: bool | None = None


class ChatResponse(BaseModel):
    """Chat response model."""
    id: str
    type: str
    name: str | None
    avatar_url: str | None
    created_at: str | None
    created_by_id: str
    keep_history: bool
    is_active: bool
    members: List[dict] = []
    last_message: dict | None = None
    unread_count: int = 0


class MemberResponse(BaseModel):
    """Member response model."""
    id: str
    user_id: str
    role: str
    joined_at: str | None
    user: dict | None


@router.get("", response_model=List[ChatResponse])
async def list_chats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List all chats for current user."""
    # Get user's chat memberships with chats and latest messages
    result = await db.execute(
        select(ChatMember)
        .options(
            selectinload(ChatMember.chat).selectinload(Chat.members).selectinload(ChatMember.user),
            selectinload(ChatMember.federated_identity),
            selectinload(ChatMember.chat).selectinload(Chat.messages)
        )
        .where(ChatMember.user_id == current_user.id)
        .order_by(ChatMember.joined_at.desc())
    )
    memberships = result.scalars().all()
    
    chats = []
    for membership in memberships:
        chat = membership.chat
        if not chat.is_active:
            continue
        
        # Get last message
        last_message = None
        if chat.messages:
            sorted_messages = sorted(chat.messages, key=lambda m: m.created_at, reverse=True)
            for msg in sorted_messages:
                if not msg.is_deleted:
                    last_message = msg.to_dict(include_reactions=False)
                    break
        
        # Count unread messages (messages after last_read_message_id)
        unread_count = 0
        last_read_time = None
        if membership.last_read_message_id:
            for msg in chat.messages:
                if msg.id == membership.last_read_message_id:
                    last_read_time = msg.created_at
                    break
        
        for msg in chat.messages:
            if msg.is_deleted:
                continue
            if msg.created_at and (last_read_time is None or msg.created_at > last_read_time):
                if msg.sender_id != current_user.id:
                    unread_count += 1
        
        chats.append(ChatResponse(
            id=chat.id,
            type=chat.type.value,
            name=chat.name,
            avatar_url=chat.avatar_url,
            created_at=chat.created_at.isoformat() if chat.created_at else None,
            created_by_id=chat.created_by_id,
            keep_history=chat.keep_history,
            is_active=chat.is_active,
            members=[{
                "id": m.id,
                "user_id": m.user_id,
                "role": m.role.value,
                "joined_at": m.joined_at.isoformat() if m.joined_at else None,
                "user": m.user.to_dict() if m.user else None
            } for m in chat.members],
            last_message=last_message,
            unread_count=unread_count
        ))
    
    return chats


@router.post("", response_model=ChatResponse, status_code=status.HTTP_201_CREATED)
async def create_chat(
    chat_data: ChatCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new chat (direct or group)."""
    config = get_config()
    
    if chat_data.type == ChatType.GROUP:
        # Check if user can create groups
        if not config.auth.allow_user_group_creation and not current_user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Users are not allowed to create groups. Contact an admin."
            )
        
        if not chat_data.name:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Group name is required"
            )
        
        if len(chat_data.member_ids) < 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="At least one other member is required for a group"
            )
    
    # For direct chats, check if chat already exists
    if chat_data.type == ChatType.DIRECT:
        if not chat_data.member_ids:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Recipient user ID is required for direct message"
            )
        
        other_user_id = chat_data.member_ids[0]
        
        # Check if direct chat already exists
        result = await db.execute(
            select(Chat)
            .options(selectinload(Chat.members).selectinload(ChatMember.user),
            selectinload(ChatMember.federated_identity))
            .where(
                Chat.type == ChatType.DIRECT,
                Chat.is_active == True
            )
        )
        existing_chats = result.scalars().all()
        
        for chat in existing_chats:
            member_ids = {m.user_id for m in chat.members}
            if current_user.id in member_ids and other_user_id in member_ids:
                # Return existing chat
                members_data = [{
                    "id": m.id,
                    "user_id": m.user_id,
                    "role": m.role.value,
                    "joined_at": m.joined_at.isoformat() if m.joined_at else None,
                    "user": m.user.to_dict() if m.user else None
                } for m in chat.members]
                return ChatResponse(
                    id=chat.id,
                    type=chat.type.value,
                    name=chat.name,
                    avatar_url=chat.avatar_url,
                    created_at=chat.created_at.isoformat() if chat.created_at else None,
                    created_by_id=chat.created_by_id,
                    keep_history=chat.keep_history,
                    is_active=chat.is_active,
                    members=members_data,
                    last_message=None,
                    unread_count=0
                )
        
        # Verify other user exists (local or federated)
        other_user: Optional[User] = None
        other_username: Optional[str] = None
        other_domain: Optional[str] = None
        other_display_name: Optional[str] = None
        
        if is_federated_user(other_user_id):
            # Federated user - parse the ID and look up on remote server
            other_username, other_domain = parse_user_id(other_user_id)
            other_display_name = other_username
            
            # Try to look up the user on the federated server
            from decemsg.federation.federation_client import lookup_federated_user
            federated_user = await lookup_federated_user(other_username, other_domain)
            if federated_user:
                other_display_name = federated_user.get("display_name", other_username)
        else:
            # Local user - verify exists in DB
            other_user_result = await db.execute(select(User).where(User.id == other_user_id))
            other_user = other_user_result.scalar_one_or_none()
            if not other_user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Recipient user not found"
                )
    
    # Determine keep_history setting
    keep_history = chat_data.keep_history if chat_data.keep_history is not None else config.messaging.default_keep_history
    
    # Create chat
    chat = Chat(
        type=chat_data.type,
        name=chat_data.name if chat_data.type == ChatType.GROUP else None,
        created_by_id=current_user.id,
        keep_history=keep_history,
    )
    
    db.add(chat)
    await db.flush()
    
    # Add creator as member
    creator_membership = ChatMember(
        chat_id=chat.id,
        user_id=current_user.id,
        role=MemberRole.ADMIN if chat_data.type == ChatType.GROUP else MemberRole.MEMBER
    )
    db.add(creator_membership)
    
    # Add other members for groups
    if chat_data.type == ChatType.GROUP:
        for member_id in chat_data.member_ids:
            if member_id != current_user.id:  # Don't add creator again
                member_user_result = await db.execute(select(User).where(User.id == member_id))
                if member_user_result.scalar_one_or_none():
                    member = ChatMember(
                        chat_id=chat.id,
                        user_id=member_id,
                        role=MemberRole.MEMBER
                    )
                    db.add(member)
    
    # For direct chat, add the other user (if not same as creator)
    if chat_data.type == ChatType.DIRECT and other_user_id != current_user.id:
        other_membership = ChatMember(
            chat_id=chat.id,
            user_id=other_user_id,
            role=MemberRole.MEMBER
        )
        db.add(other_membership)
        
        # If this is a federated chat, sync with remote server
        if is_federated_user(other_user_id) and other_domain:
            from decemsg.federation.federation_client import sync_chat_members
            await sync_chat_members(
                chat_id=chat.id,
                local_members=[current_user.id],
                remote_domains=[other_domain]
            )
    
    await db.commit()
    
    # Reload chat with members
    result = await db.execute(
        select(Chat)
        .options(selectinload(Chat.members).selectinload(ChatMember.user),
            selectinload(ChatMember.federated_identity))
        .where(Chat.id == chat.id)
    )
    chat = result.scalar_one()
    
    members_data = [{
        "id": m.id,
        "user_id": m.user_id,
        "role": m.role.value,
        "joined_at": m.joined_at.isoformat() if m.joined_at else None,
        "user": m.user.to_dict() if m.user else None
    } for m in chat.members]
    
    return ChatResponse(
        id=chat.id,
        type=chat.type.value,
        name=chat.name,
        avatar_url=chat.avatar_url,
        created_at=chat.created_at.isoformat() if chat.created_at else None,
        created_by_id=chat.created_by_id,
        keep_history=chat.keep_history,
        is_active=chat.is_active,
        members=members_data,
        last_message=None,
        unread_count=0
    )


@router.get("/{chat_id}", response_model=ChatResponse)
async def get_chat(
    chat_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get chat details."""
    result = await db.execute(
        select(Chat)
        .options(selectinload(Chat.members).selectinload(ChatMember.user),
            selectinload(ChatMember.federated_identity))
        .where(Chat.id == chat_id)
    )
    chat = result.scalar_one_or_none()
    
    if not chat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat not found"
        )
    
    # Check if user is a member
    is_member = any(m.user_id == current_user.id for m in chat.members)
    if not is_member:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not a member of this chat"
        )
    
    members_data = [{
        "id": m.id,
        "user_id": m.user_id,
        "role": m.role.value,
        "joined_at": m.joined_at.isoformat() if m.joined_at else None,
        "user": m.user.to_dict() if m.user else None
    } for m in chat.members]
    
    return ChatResponse(
        id=chat.id,
        type=chat.type.value,
        name=chat.name,
        avatar_url=chat.avatar_url,
        created_at=chat.created_at.isoformat() if chat.created_at else None,
        created_by_id=chat.created_by_id,
        keep_history=chat.keep_history,
        is_active=chat.is_active,
        members=members_data,
        last_message=None,
        unread_count=0
    )


@router.put("/{chat_id}", response_model=ChatResponse)
async def update_chat(
    chat_id: str,
    update_data: ChatUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update chat details."""
    result = await db.execute(
        select(Chat)
        .options(selectinload(Chat.members).selectinload(ChatMember.user),
            selectinload(ChatMember.federated_identity))
        .where(Chat.id == chat_id)
    )
    chat = result.scalar_one_or_none()
    
    if not chat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat not found"
        )
    
    # Check if user is admin of the chat
    user_membership = next((m for m in chat.members if m.user_id == current_user.id), None)
    if not user_membership or (user_membership.role != MemberRole.ADMIN and not current_user.is_admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this chat"
        )
    
    if update_data.name is not None:
        chat.name = update_data.name
    if update_data.avatar_url is not None:
        chat.avatar_url = update_data.avatar_url
    if update_data.keep_history is not None:
        chat.keep_history = update_data.keep_history
    
    await db.commit()
    await db.refresh(chat)
    
    members_data = [{
        "id": m.id,
        "user_id": m.user_id,
        "role": m.role.value,
        "joined_at": m.joined_at.isoformat() if m.joined_at else None,
        "user": m.user.to_dict() if m.user else None
    } for m in chat.members]
    
    return ChatResponse(
        id=chat.id,
        type=chat.type.value,
        name=chat.name,
        avatar_url=chat.avatar_url,
        created_at=chat.created_at.isoformat() if chat.created_at else None,
        created_by_id=chat.created_by_id,
        keep_history=chat.keep_history,
        is_active=chat.is_active,
        members=members_data,
        last_message=None,
        unread_count=0
    )


@router.post("/{chat_id}/members/{user_id}", status_code=status.HTTP_201_CREATED)
async def add_member(
    chat_id: str,
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Add a member to a chat."""
    result = await db.execute(
        select(Chat)
        .options(selectinload(Chat.members).selectinload(ChatMember.federated_identity))
        .where(Chat.id == chat_id)
    )
    chat = result.scalar_one_or_none()
    
    if not chat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat not found"
        )
    
    # Check if current user is admin of the chat
    user_membership = next((m for m in chat.members if m.user_id == current_user.id), None)
    if not user_membership or (user_membership.role != MemberRole.ADMIN and not current_user.is_admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to add members"
        )
    
    # Check if user exists
    user_result = await db.execute(select(User).where(User.id == user_id))
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Check if already a member
    if any(m.user_id == user_id for m in chat.members):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User is already a member"
        )
    
    member = ChatMember(
        chat_id=chat_id,
        user_id=user_id,
        role=MemberRole.MEMBER
    )
    db.add(member)
    await db.commit()
    
    return {"message": "Member added successfully"}


@router.delete("/{chat_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    chat_id: str,
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Remove a member from a chat."""
    result = await db.execute(
        select(Chat)
        .options(selectinload(Chat.members).selectinload(ChatMember.federated_identity))
        .where(Chat.id == chat_id)
    )
    chat = result.scalar_one_or_none()
    
    if not chat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat not found"
        )
    
    # Check if current user is admin or removing themselves
    user_membership = next((m for m in chat.members if m.user_id == current_user.id), None)
    is_admin = user_membership and user_membership.role == MemberRole.ADMIN
    
    if current_user.id != user_id and not is_admin and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to remove members"
        )
    
    # Find and remove membership
    membership = next((m for m in chat.members if m.user_id == user_id), None)
    if membership:
        await db.delete(membership)
        await db.commit()
