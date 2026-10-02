"""Security regression tests for signed federation event envelopes."""

import base64

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from pydantic import ValidationError

from decemsg.federation.events import (
    FederationEventEnvelope,
    canonical_event_bytes,
    verify_event_signature,
)


@pytest.mark.security
def test_event_canonicalization_is_deterministic() -> None:
    left = {
        "ciphertext": "opaque",
        "event_id": "event-1",
        "sequence": 1,
    }
    right = {
        "sequence": 1,
        "event_id": "event-1",
        "ciphertext": "opaque",
    }
    assert canonical_event_bytes(left) == canonical_event_bytes(right)


@pytest.mark.security
def test_event_signature_rejects_tampering() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    event = {
        "event_id": "event-1",
        "event_type": "message",
        "protocol_version": "1",
        "origin_server": "example.com",
        "origin_key_id": "key-1",
        "actor_identity": "alice#example.com",
        "target_identity": "bob#remote.example",
        "conversation_id": "chat-1",
        "created_at": "2026-10-02T00:00:00",
        "sequence": 0,
        "message_type": "text",
        "ciphertext": "opaque-ciphertext",
        "signature": None,
    }

    der = private_key.sign(
        canonical_event_bytes(event),
        ec.ECDSA(hashes.SHA256()),
    )
    r, s = decode_dss_signature(der)
    event["signature"] = base64.b64encode(
        r.to_bytes(32, "big") + s.to_bytes(32, "big")
    ).decode("ascii")

    assert verify_event_signature(event, public_pem)

    tampered = dict(event)
    tampered["ciphertext"] = "different-ciphertext"
    assert not verify_event_signature(tampered, public_pem)

@pytest.mark.security
def test_event_schema_rejects_unknown_fields_and_wrong_version() -> None:
    base = {
        "event_id": "event-1",
        "event_type": "message",
        "protocol_version": "1",
        "origin_server": "example.com",
        "origin_key_id": "key-1",
        "actor_identity": "alice#example.com",
        "target_identity": "bob#remote.example",
        "conversation_id": "chat-1",
        "created_at": "2026-10-02T00:00:00",
        "sequence": 0,
        "message_type": "text",
        "ciphertext": "opaque",
        "signature": "sig",
    }

    FederationEventEnvelope.model_validate(base)

    with pytest.raises(ValidationError):
        FederationEventEnvelope.model_validate({**base, "unexpected": True})

    with pytest.raises(ValidationError):
        FederationEventEnvelope.model_validate({**base, "protocol_version": "2"})


@pytest.mark.security
def test_event_schema_requires_nonempty_identifier_and_nonnegative_sequence() -> None:
    base = {
        "event_id": "",
        "event_type": "message",
        "protocol_version": "1",
        "origin_server": "example.com",
        "origin_key_id": "key-1",
        "actor_identity": "alice#example.com",
        "target_identity": "bob#remote.example",
        "conversation_id": "chat-1",
        "created_at": "2026-10-02T00:00:00",
        "sequence": -1,
        "message_type": "text",
        "ciphertext": "opaque",
        "signature": "sig",
    }

    with pytest.raises(ValidationError):
        FederationEventEnvelope.model_validate(base)
