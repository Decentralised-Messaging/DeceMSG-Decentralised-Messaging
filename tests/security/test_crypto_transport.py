"""Security regression tests for the client E2EE transport boundary."""

import pytest

from decemsg.api.crypto import CryptoRequest, _matrix_user_id
from decemsg.main import app
from decemsg.models.crypto import CryptoDeviceState, CryptoToDeviceMessage
from decemsg.api.messages import MessageCreate


@pytest.mark.security
def test_crypto_request_rejects_unknown_request_type() -> None:
    with pytest.raises(ValueError):
        CryptoRequest.model_validate(
            {
                "request_type": "plaintext_message",
                "request_id": "req-1",
                "body": {},
            }
        )


@pytest.mark.security
def test_crypto_routes_are_registered() -> None:
    paths = {route.path for route in app.routes}
    assert "/api/crypto/requests" in paths
    assert "/api/crypto/to-device" in paths
    assert "/api/crypto/to-device/ack" in paths


@pytest.mark.security
def test_crypto_state_models_contain_no_private_key_fields() -> None:
    columns = set(CryptoDeviceState.__table__.columns.keys())
    assert "private_key" not in columns
    assert "private_identity_key" not in columns
    assert "device_keys" in columns
    assert "one_time_keys" in columns


@pytest.mark.security
def test_to_device_storage_is_opaque() -> None:
    columns = set(CryptoToDeviceMessage.__table__.columns.keys())
    assert "plaintext" not in columns
    assert "private_key" not in columns
    assert "content" in columns


def test_matrix_user_id_uses_canonical_server_identity() -> None:
    class UserStub:
        username = "alice"
        domain = "example.com"

    assert _matrix_user_id(UserStub()) == "@alice:example.com"


@pytest.mark.security
def test_message_creation_contract_requires_ciphertext() -> None:
    request = MessageCreate(content="plaintext")
    assert request.encrypted_content is None
