"""First-class device identity model."""

import uuid
from datetime import datetime
from enum import Enum

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Enum as SAEnum, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from decemsg.core.database import Base


class DeviceStatus(str, Enum):
    """Lifecycle state for a user's device identity."""

    ACTIVE = "active"
    REVOKED = "revoked"


class Device(Base):
    """A stable per-client cryptographic device identity."""

    __tablename__ = "devices"
    __table_args__ = (
        UniqueConstraint("user_id", "public_identity_key", name="uq_device_user_public_key"),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    platform: Mapped[str] = mapped_column(String(50), nullable=False)
    public_identity_key: Mapped[str] = mapped_column(
        String(4096),
        nullable=False,
    )
    status: Mapped[DeviceStatus] = mapped_column(
        SAEnum(DeviceStatus),
        default=DeviceStatus.ACTIVE,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    user: Mapped["User"] = relationship("User", back_populates="devices")
