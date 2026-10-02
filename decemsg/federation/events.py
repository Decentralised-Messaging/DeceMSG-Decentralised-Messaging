"""Signed federation event envelope for deterministic server-to-server events."""

import base64
import json
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field
from uuid import uuid4

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from decemsg.core.config import get_config
from decemsg.federation.server_auth import get_key_manager


PROTOCOL_VERSION = "1"



class FederationEventEnvelope(BaseModel):
    """Validated wire schema for a signed federation event."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(..., min_length=1, max_length=255)
    event_type: Literal["message"]
    protocol_version: Literal["1"]
    origin_server: str = Field(..., min_length=1, max_length=255)
    origin_key_id: str = Field(..., min_length=1, max_length=255)
    actor_identity: str = Field(..., min_length=3, max_length=511)
    target_identity: str = Field(..., min_length=3, max_length=511)
    conversation_id: str = Field(..., min_length=1, max_length=255)
    created_at: str = Field(..., min_length=1, max_length=64)
    sequence: int = Field(..., ge=0)
    message_type: str = Field(..., min_length=1, max_length=64)
    ciphertext: str = Field(..., min_length=1, max_length=1_000_000)
    signature: str = Field(..., min_length=1, max_length=1024)


def canonical_event_bytes(event: dict[str, Any]) -> bytes:
    unsigned = {key: value for key, value in event.items() if key != "signature"}
    return json.dumps(
        unsigned,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sign_event(event: dict[str, Any]) -> dict[str, Any]:
    payload = dict(event)
    payload["signature"] = None
    key_manager = get_key_manager()
    signature = key_manager.sign_data(canonical_event_bytes(payload).decode("utf-8"))
    payload["signature"] = signature
    return payload


def build_message_event(
    *,
    actor_identity: str,
    target_identity: str,
    conversation_id: str,
    ciphertext: str,
    message_type: str,
    sequence: int = 0,
) -> dict[str, Any]:
    config = get_config()
    key_manager = get_key_manager()
    event = {
        "event_id": str(uuid4()),
        "event_type": "message",
        "protocol_version": PROTOCOL_VERSION,
        "origin_server": config.server.domain,
        "origin_key_id": key_manager.get_key_id(),
        "actor_identity": actor_identity,
        "target_identity": target_identity,
        "conversation_id": conversation_id,
        "created_at": datetime.utcnow().isoformat(),
        "sequence": sequence,
        "message_type": message_type,
        "ciphertext": ciphertext,
        "signature": None,
    }
    return sign_event(event)


def verify_event_signature(event: dict[str, Any], public_key_pem: str) -> bool:
    signature = event.get("signature")
    if not signature:
        return False

    try:
        raw = base64.b64decode(signature, validate=True)
        if len(raw) != 64:
            return False
        r = int.from_bytes(raw[:32], "big")
        s = int.from_bytes(raw[32:], "big")
        der_signature = encode_dss_signature(r, s)

        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            return False

        public_key.verify(
            der_signature,
            canonical_event_bytes(event),
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except Exception:
        return False
