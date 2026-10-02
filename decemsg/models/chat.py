"""DeceMSG Chat model."""
import uuid
from datetime import datetime
from enum import Enum as PyEnum
from sqlalchemy import String, Boolean, DateTime, ForeignKey, Enum, Text, CheckConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from decemsg.core.database import Base


class ChatType(str, PyEnum):
    """Chat type enumeration."""
    DIRECT = "direct"
    GROUP = "group"


class MemberRole(str, PyEnum):
    """Member role in a chat."""
    MEMBER = "member"
    ADMIN = "admin"


class Chat(Base):
    """Chat model for conversations."""
    
    __tablename__ = "chats"
    
    id: Mapped[str] = mapped_column(
        String(36), 
        primary_key=True, 
        default=lambda: str(uuid.uuid4())
    )
    type: Mapped[ChatType] = mapped_column(
        Enum(ChatType), 
        default=ChatType.DIRECT, 
        nullable=False
    )
    name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    avatar_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, 
        default=datetime.utcnow,
        nullable=False
    )
    created_by_id: Mapped[str] = mapped_column(
        String(36), 
        ForeignKey("users.id"),
        nullable=False
    )
    keep_history: Mapped[bool] = mapped_column(
        Boolean, 
        default=True,
        nullable=False
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, 
        default=True,
        nullable=False
    )
    
    # Relationships
    created_by: Mapped["User"] = relationship(
        "User",
        foreign_keys=[created_by_id],
        backref="created_chats"
    )
    members: Mapped[list["ChatMember"]] = relationship(
        "ChatMember",
        back_populates="chat",
        cascade="all, delete-orphan"
    )
    messages: Mapped[list["Message"]] = relationship(
        "Message",
        back_populates="chat",
        cascade="all, delete-orphan",
        order_by="Message.created_at"
    )
    
    def to_dict(self, include_members: bool = False) -> dict:
        """Convert chat to dictionary."""
        data = {
            "id": self.id,
            "type": self.type.value,
            "name": self.name,
            "avatar_url": self.avatar_url,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "created_by_id": self.created_by_id,
            "keep_history": self.keep_history,
            "is_active": self.is_active,
        }
        if include_members:
            data["members"] = [m.to_dict() for m in self.members]
        return data


class ChatMember(Base):
    """ChatMember model for user-chat relationships."""
    
    __tablename__ = "chat_members"
    __table_args__ = (
        CheckConstraint(
            "(user_id IS NOT NULL) OR (federated_identity_id IS NOT NULL)",
            name="ck_chat_member_has_identity",
        ),
        CheckConstraint(
            "NOT (user_id IS NOT NULL AND federated_identity_id IS NOT NULL)",
            name="ck_chat_member_one_identity",
        ),
    )
    
    id: Mapped[str] = mapped_column(
        String(36), 
        primary_key=True, 
        default=lambda: str(uuid.uuid4())
    )
    chat_id: Mapped[str] = mapped_column(
        String(36), 
        ForeignKey("chats.id", ondelete="CASCADE"),
        nullable=False
    )
    user_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
    )
    federated_identity_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("federated_identities.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    role: Mapped[MemberRole] = mapped_column(
        Enum(MemberRole),
        default=MemberRole.MEMBER,
        nullable=False
    )
    joined_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )
    last_read_message_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("messages.id", ondelete="SET NULL"),
        nullable=True
    )
    
    # Relationships
    chat: Mapped["Chat"] = relationship("Chat", back_populates="members")
    user: Mapped["User | None"] = relationship("User", back_populates="chat_memberships")
    federated_identity: Mapped["FederatedIdentity | None"] = relationship(
        "FederatedIdentity",
        back_populates="chat_memberships",
    )
    
    def to_dict(self) -> dict:
        """Convert chat member to dictionary."""
        return {
            "id": self.id,
            "chat_id": self.chat_id,
            "user_id": self.user_id,
            "federated_identity_id": self.federated_identity_id,
            "role": self.role.value,
            "joined_at": self.joined_at.isoformat() if self.joined_at else None,
            "last_read_message_id": self.last_read_message_id,
            "user": self.user.to_dict() if self.user else None,
            "federated_identity": {
                "id": self.federated_identity.id,
                "username": self.federated_identity.username,
                "domain": self.federated_identity.domain,
                "display_name": self.federated_identity.display_name,
                "avatar_url": self.federated_identity.avatar_url,
            } if self.federated_identity else None,
        }


# Import at bottom to avoid circular imports
from decemsg.models.user import User
from decemsg.models.message import Message
from decemsg.models.federated_identity import FederatedIdentity
