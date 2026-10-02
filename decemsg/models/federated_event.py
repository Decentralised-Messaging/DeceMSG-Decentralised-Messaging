"""Persistent federation event replay/idempotency state."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from decemsg.core.database import Base


class FederatedEventState(Base):
    """Durable receipt/order state for signed federation events."""

    __tablename__ = "federated_event_states"
    __table_args__ = (
        UniqueConstraint("event_id", name="uq_federated_event_event_id"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    event_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    origin_server: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    actor_identity: Mapped[str] = mapped_column(String(511), nullable=False, index=True)
    conversation_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    accepted_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
