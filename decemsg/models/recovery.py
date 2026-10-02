"""Opaque encrypted identity backup storage."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from decemsg.core.database import Base


class IdentityRecoveryBackup(Base):
    """Client-encrypted identity backup; the server cannot decrypt it."""

    __tablename__ = "identity_recovery_backups"
    __table_args__ = (
        UniqueConstraint("user_id", name="uq_identity_recovery_backup_user"),
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
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    kdf_algorithm: Mapped[str] = mapped_column(String(32), nullable=False)
    kdf_memory_kib: Mapped[int] = mapped_column(Integer, nullable=False)
    kdf_iterations: Mapped[int] = mapped_column(Integer, nullable=False)
    kdf_parallelism: Mapped[int] = mapped_column(Integer, nullable=False)
    kdf_salt: Mapped[str] = mapped_column(String(256), nullable=False)
    encryption_algorithm: Mapped[str] = mapped_column(String(64), nullable=False)
    encryption_nonce: Mapped[str] = mapped_column(String(256), nullable=False)
    ciphertext: Mapped[str] = mapped_column(String(1_000_000), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    user: Mapped["User"] = relationship("User", backref="identity_recovery_backup")
