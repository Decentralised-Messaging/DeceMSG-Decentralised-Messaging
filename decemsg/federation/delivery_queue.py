"""Durable outbound federation delivery queue and worker."""

import asyncio
import json
import logging
import socket
from datetime import datetime, timedelta
from uuid import uuid4

from sqlalchemy import and_, or_, select, update
from sqlalchemy.exc import IntegrityError

from decemsg.core.database import get_session_factory
from decemsg.models.federation_delivery import FederationDeliveryJob

logger = logging.getLogger(__name__)

LEASE_SECONDS = 60
POLL_SECONDS = 1
BACKOFF_SECONDS = (5, 15, 60, 300, 900, 1800, 3600, 7200)


async def add_federation_delivery_job(
    db,
    *,
    idempotency_key: str,
    job_type: str,
    destination_domain: str,
    payload: dict,
    max_attempts: int = 8,
) -> FederationDeliveryJob:
    """Add an outbound job to an existing transaction."""
    existing = await db.execute(
        select(FederationDeliveryJob).where(
            FederationDeliveryJob.idempotency_key == idempotency_key
        )
    )
    job = existing.scalar_one_or_none()
    if job is not None:
        return job

    job = FederationDeliveryJob(
        idempotency_key=idempotency_key,
        job_type=job_type,
        destination_domain=destination_domain,
        payload=json.dumps(payload, separators=(",", ":"), ensure_ascii=False),
        max_attempts=max(1, max_attempts),
    )
    db.add(job)
    await db.flush()
    return job


async def enqueue_federation_delivery(
    *,
    idempotency_key: str,
    job_type: str,
    destination_domain: str,
    payload: dict,
    max_attempts: int = 8,
) -> bool:
    """Atomically enqueue an outbound federation operation.

    Returns True when the job exists after the operation. Existing idempotency
    keys are treated as successful enqueue requests.
    """
    factory = get_session_factory()
    async with factory() as db:
        existing = await db.execute(
            select(FederationDeliveryJob).where(
                FederationDeliveryJob.idempotency_key == idempotency_key
            )
        )
        if existing.scalar_one_or_none() is not None:
            return True

        db.add(
            FederationDeliveryJob(
                idempotency_key=idempotency_key,
                job_type=job_type,
                destination_domain=destination_domain,
                payload=json.dumps(payload, separators=(",", ":"), ensure_ascii=False),
                max_attempts=max(1, max_attempts),
            )
        )
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()
            return True
        return True


async def claim_delivery_job(worker_id: str) -> FederationDeliveryJob | None:
    """Atomically claim one pending or expired leased job."""
    factory = get_session_factory()
    async with factory() as db:
        now = datetime.utcnow()
        candidate = (
            select(FederationDeliveryJob.id)
            .where(
                FederationDeliveryJob.status.in_(["pending", "inflight"]),
                FederationDeliveryJob.available_at <= now,
                or_(
                    FederationDeliveryJob.status == "pending",
                    and_(
                        FederationDeliveryJob.status == "inflight",
                        FederationDeliveryJob.lease_until < now,
                    ),
                ),
            )
            .order_by(FederationDeliveryJob.created_at.asc(), FederationDeliveryJob.id.asc())
            .limit(1)
            .scalar_subquery()
        )
        result = await db.execute(
            update(FederationDeliveryJob)
            .where(FederationDeliveryJob.id == candidate)
            .values(
                status="inflight",
                worker_id=worker_id,
                lease_until=now + timedelta(seconds=LEASE_SECONDS),
                attempts=FederationDeliveryJob.attempts + 1,
            )
        )
        if result.rowcount != 1:
            await db.rollback()
            return None

        claimed = await db.execute(
            select(FederationDeliveryJob).where(
                FederationDeliveryJob.worker_id == worker_id,
                FederationDeliveryJob.status == "inflight",
            ).order_by(FederationDeliveryJob.created_at.asc()).limit(1)
        )
        job = claimed.scalar_one_or_none()
        if job is None:
            await db.rollback()
            return None
        await db.commit()
        return job


async def complete_delivery_job(job_id: str, worker_id: str) -> None:
    factory = get_session_factory()
    async with factory() as db:
        await db.execute(
            update(FederationDeliveryJob)
            .where(
                FederationDeliveryJob.id == job_id,
                FederationDeliveryJob.worker_id == worker_id,
                FederationDeliveryJob.status == "inflight",
            )
            .values(
                status="completed",
                lease_until=None,
                completed_at=datetime.utcnow(),
                last_error=None,
            )
        )
        await db.commit()


async def fail_delivery_job(job: FederationDeliveryJob, worker_id: str, error: Exception) -> None:
    factory = get_session_factory()
    async with factory() as db:
        current = await db.execute(
            select(FederationDeliveryJob).where(
                FederationDeliveryJob.id == job.id,
                FederationDeliveryJob.worker_id == worker_id,
                FederationDeliveryJob.status == "inflight",
            )
        )
        row = current.scalar_one_or_none()
        if row is None:
            await db.rollback()
            return

        message = str(error)[:2000]
        if row.attempts >= row.max_attempts:
            row.status = "dead"
            row.lease_until = None
            row.last_error = message
        else:
            delay = BACKOFF_SECONDS[min(row.attempts - 1, len(BACKOFF_SECONDS) - 1)]
            row.status = "pending"
            row.available_at = datetime.utcnow() + timedelta(seconds=delay)
            row.lease_until = None
            row.worker_id = None
            row.last_error = message
        await db.commit()


async def process_delivery_job(job: FederationDeliveryJob) -> None:
    """Deliver a claimed job without recursively enqueueing it."""
    if job.job_type != "message":
        raise ValueError(f"Unsupported federation job type: {job.job_type}")

    from decemsg.federation.discovery import get_federation_client

    payload = json.loads(job.payload)
    client = get_federation_client()
    success = await client.send_message(
        from_user=payload["from_user"],
        from_domain=payload["from_domain"],
        to_user=payload["to_user"],
        to_domain=payload["to_domain"],
        content=payload["content"],
        message_type=payload["message_type"],
        event=payload["event"],
    )
    if not success:
        raise RuntimeError("Federation delivery returned a non-success response")


async def federation_delivery_worker(stop_event: asyncio.Event) -> None:
    """Run a lease-based worker suitable for every application process."""
    worker_id = f"{socket.gethostname()}:{uuid4()}"
    while not stop_event.is_set():
        job = None
        try:
            job = await claim_delivery_job(worker_id)
            if job is None:
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=POLL_SECONDS)
                except asyncio.TimeoutError:
                    pass
                continue

            try:
                await process_delivery_job(job)
            except Exception as exc:
                logger.warning("Federation job %s failed: %s", job.id, exc)
                await fail_delivery_job(job, worker_id, exc)
            else:
                await complete_delivery_job(job.id, worker_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Federation delivery worker iteration failed")
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=POLL_SECONDS)
            except asyncio.TimeoutError:
                pass
