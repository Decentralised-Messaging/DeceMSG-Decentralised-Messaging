"""Remote/federated user identity model."""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from decemsg.core.database import Base


class FederatedIdentity(Base):
    """A remote DeceMSG identity, distinct from a local authenticated User."""

    __tablename__ = "federated_identities"
    __table_args__ = (
        UniqueConstraint("username", "domain", name="uq_federated_identity_address"),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    username: Mapped[str] = mapped_column(String(50), nullable=False)
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    avatar_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    public_key: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    chat_memberships: Mapped[list["ChatMember"]] = relationship(
        "ChatMember",
        back_populates="federated_identity",
    )
    messages: Mapped[list["Message"]] = relationship(
        "Message",
        back_populates="sender_federated_identity",
    )

    @property
    def full_address(self) -> str:
        return f"{self.username}#{self.domain}"
