"""Durable federation delivery jobs."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from decemsg.core.database import Base


class FederationDeliveryJob(Base):
    """Transactional outbound federation job with lease/retry state."""

    __tablename__ = "federation_delivery_jobs"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_federation_delivery_idempotency"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    job_type: Mapped[str] = mapped_column(String(64), nullable=False)
    destination_domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    payload: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", index=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=8)
    available_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False, index=True
    )
    lease_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    worker_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False, index=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
