"""DeceMSG Message model."""
import uuid
from datetime import datetime
from enum import Enum as PyEnum
from sqlalchemy import String, DateTime, ForeignKey, Enum, Text, Integer, Boolean, CheckConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from decemsg.core.database import Base


class MessageType(str, PyEnum):
    """Message type enumeration."""
    TEXT = "text"
    IMAGE = "image"
    FILE = "file"
    SYSTEM = "system"


class Message(Base):
    """Message model for chat messages."""
    
    __tablename__ = "messages"
    __table_args__ = (
        CheckConstraint(
            "(sender_id IS NULL) OR (sender_federated_identity_id IS NULL)",
            name="ck_message_one_sender_identity",
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
    sender_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    sender_federated_identity_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("federated_identities.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)
    message_type: Mapped[MessageType] = mapped_column(
        Enum(MessageType),
        default=MessageType.TEXT,
        nullable=False
    )
    file_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    file_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    file_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    is_deleted: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False
    )
    reply_to_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("messages.id", ondelete="SET NULL"),
        nullable=True
    )
    
    # Delivery status
    is_delivered: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False
    )
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    is_read: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False
    )
    read_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    
    # Relationships
    chat: Mapped["Chat"] = relationship("Chat", back_populates="messages")
    sender: Mapped["User | None"] = relationship(
        "User",
        back_populates="sent_messages",
        foreign_keys=[sender_id],
    )
    sender_federated_identity: Mapped["FederatedIdentity | None"] = relationship(
        "FederatedIdentity",
        back_populates="messages",
        foreign_keys=[sender_federated_identity_id],
    )
    reactions: Mapped[list["MessageReaction"]] = relationship(
        "MessageReaction",
        back_populates="message",
        cascade="all, delete-orphan"
    )
    reply_to: Mapped["Message"] = relationship(
        "Message",
        remote_side=[id],
        foreign_keys=[reply_to_id]
    )
    
    def to_dict(self, include_reactions: bool = True) -> dict:
        """Convert message to dictionary."""
        data = {
            "id": self.id,
            "chat_id": self.chat_id,
            "sender_id": self.sender_id,
            "sender_federated_identity_id": self.sender_federated_identity_id,
            "content": self.content,
            "message_type": self.message_type.value,
            "file_url": self.file_url,
            "file_name": self.file_name,
            "file_size": self.file_size,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_deleted": self.is_deleted,
            "reply_to_id": self.reply_to_id,
            "is_delivered": self.is_delivered,
            "delivered_at": self.delivered_at.isoformat() if self.delivered_at else None,
            "is_read": self.is_read,
            "read_at": self.read_at.isoformat() if self.read_at else None,
        }
        
        if include_reactions:
            # Aggregate reactions by emoji
            reaction_summary = {}
            for reaction in self.reactions:
                if reaction.emoji not in reaction_summary:
                    reaction_summary[reaction.emoji] = {
                        "count": 0,
                        "user_ids": []
                    }
                reaction_summary[reaction.emoji]["count"] += 1
                if self.sender_id:  # Include sender_id for current user check
                    reaction_summary[reaction.emoji]["user_ids"].append(reaction.user_id)
            data["reactions"] = reaction_summary
        
        # Include sender info if available
        if self.sender:
            data["sender"] = {
                "id": self.sender.id,
                "username": self.sender.username,
                "display_name": self.sender.display_name,
                "avatar_url": self.sender.avatar_url,
                "domain": self.sender.domain,
            }
        elif self.sender_federated_identity:
            data["sender"] = {
                "id": self.sender_federated_identity.id,
                "username": self.sender_federated_identity.username,
                "display_name": self.sender_federated_identity.display_name,
                "avatar_url": self.sender_federated_identity.avatar_url,
                "domain": self.sender_federated_identity.domain,
            }
        
        return data


class MessageReaction(Base):
    """MessageReaction model for message reactions."""
    
    __tablename__ = "message_reactions"
    
    id: Mapped[str] = mapped_column(
        String(36), 
        primary_key=True, 
        default=lambda: str(uuid.uuid4())
    )
    message_id: Mapped[str] = mapped_column(
        String(36), 
        ForeignKey("messages.id", ondelete="CASCADE"),
        nullable=False
    )
    user_id: Mapped[str] = mapped_column(
        String(36), 
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False
    )
    emoji: Mapped[str] = mapped_column(String(10), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )
    
    # Relationships
    message: Mapped["Message"] = relationship("Message", back_populates="reactions")
    user: Mapped["User"] = relationship("User")
    
    def to_dict(self) -> dict:
        """Convert reaction to dictionary."""
        return {
            "id": self.id,
            "message_id": self.message_id,
            "user_id": self.user_id,
            "emoji": self.emoji,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


# Import at bottom to avoid circular imports
from decemsg.models.user import User
from decemsg.models.chat import Chat
from decemsg.models.federated_identity import FederatedIdentity
