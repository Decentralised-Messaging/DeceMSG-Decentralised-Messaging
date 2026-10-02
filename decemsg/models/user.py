"""DeceMSG User model."""
import uuid
from datetime import datetime
from sqlalchemy import String, Boolean, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.sqlite import JSON

from decemsg.core.database import Base


class User(Base):
    """User model for authentication and identity."""
    
    __tablename__ = "users"
    
    id: Mapped[str] = mapped_column(
        String(36), 
        primary_key=True, 
        default=lambda: str(uuid.uuid4())
    )
    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(100), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    domain: Mapped[str] = mapped_column(String(255), nullable=False, default="localhost")
    avatar_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, 
        default=datetime.utcnow,
        nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime, 
        default=datetime.utcnow,
        nullable=True
    )
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    
    # Relationships
    sent_messages: Mapped[list["Message"]] = relationship(
        "Message", 
        back_populates="sender",
        foreign_keys="Message.sender_id"
    )
    chat_memberships: Mapped[list["ChatMember"]] = relationship(
        "ChatMember",
        back_populates="user",
        cascade="all, delete-orphan"
    )
    identity: Mapped["UserIdentity | None"] = relationship(
        "UserIdentity",
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
    )
    devices: Mapped[list["Device"]] = relationship(
        "Device",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    
    @property
    def full_address(self) -> str:
        """Get full user address (username#domain)."""
        return f"{self.username}#{self.domain}"
    
    def to_dict(self, include_sensitive: bool = False) -> dict:
        """Convert user to dictionary."""
        data = {
            "id": self.id,
            "username": self.username,
            "display_name": self.display_name,
            "domain": self.domain,
            "avatar_url": self.avatar_url,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "is_active": self.is_active,
        }
        if include_sensitive:
            data["is_admin"] = self.is_admin
        return data


# Import at bottom to avoid circular imports
from decemsg.models.message import Message
from decemsg.models.chat import ChatMember


from decemsg.models.identity import UserIdentity
from decemsg.models.device import Device
