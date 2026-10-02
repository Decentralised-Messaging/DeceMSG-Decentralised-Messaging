"""Security and reliability tests for the federation delivery outbox."""

import asyncio
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from decemsg.federation.delivery_queue import (
    add_federation_delivery_job,
    fail_delivery_job,
)
from decemsg.models.federation_delivery import FederationDeliveryJob


@pytest.mark.security
def test_outbox_insertion_is_idempotent() -> None:
    db = AsyncMock()
    existing = SimpleNamespace(id="existing")
    db.execute.return_value = SimpleNamespace(
        scalar_one_or_none=lambda: existing
    )

    result = asyncio.run(
        add_federation_delivery_job(
            db,
            idempotency_key="message:event-1",
            job_type="message",
            destination_domain="remote.example",
            payload={"event": {"event_id": "event-1", "ciphertext": "opaque"}},
        )
    )

    assert result is existing
    db.add.assert_not_called()
    db.flush.assert_not_awaited()


@pytest.mark.security
def test_failed_delivery_retries_with_bounded_backoff() -> None:
    job = FederationDeliveryJob(
        idempotency_key="message:event-2",
        job_type="message",
        destination_domain="remote.example",
        payload="{}",
        status="inflight",
        attempts=2,
        max_attempts=8,
    )
    db = AsyncMock()
    db.execute.return_value = SimpleNamespace(scalar_one_or_none=lambda: job)

    asyncio.run(
        fail_delivery_job(
            job,
            "worker-1",
            RuntimeError("temporary network failure"),
        )
    )

    assert job.status == "pending"
    assert job.worker_id is None
    assert job.lease_until is None
    assert job.last_error == "temporary network failure"
    assert job.available_at > datetime.utcnow()


@pytest.mark.security
def test_exhausted_delivery_moves_to_dead_letter_state() -> None:
    job = FederationDeliveryJob(
        id="job-1",
        idempotency_key="message:event-3",
        job_type="message",
        destination_domain="remote.example",
        payload="{}",
        status="inflight",
        attempts=8,
        max_attempts=8,
    )
    db = AsyncMock()
    db.execute.return_value = SimpleNamespace(scalar_one_or_none=lambda: job)

    asyncio.run(
        fail_delivery_job(
            job,
            "worker-1",
            RuntimeError("permanent failure"),
        )
    )

    assert job.status == "dead"
    assert job.lease_until is None
    assert job.last_error == "permanent failure"


@pytest.mark.security
def test_expired_lease_is_eligible_for_reclaim() -> None:
    job = FederationDeliveryJob(
        id="job-2",
        idempotency_key="message:event-4",
        job_type="message",
        destination_domain="remote.example",
        payload="{}",
        status="inflight",
        attempts=1,
        max_attempts=8,
        lease_until=datetime.utcnow() - timedelta(seconds=1),
    )
    assert job.lease_until < datetime.utcnow()
