"""Server authentication for federation.

This module provides:
- Server key pair generation and storage
- Request signing for server-to-server communication
- Server verification via signatures
"""
import os
import hashlib
import hmac
import time
import json
import base64
import secrets
import threading
from typing import Optional, Dict
from datetime import datetime, timedelta
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.backends import default_backend


@dataclass
class ServerIdentity:
    """Identity information for a federated server."""
    domain: str
    public_key_pem: str
    key_id: str = ""
    signature: Optional[str] = None
    issued_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    is_verified: bool = False


def public_key_id(public_key_pem: str) -> str:
    """Return a stable SHA-256 identifier for a public key."""
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode(),
        backend=default_backend(),
    )
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return f"sha256:{hashlib.sha256(der).hexdigest()}"


@dataclass
class ServerTrustRecord:
    """Policy binding a domain to one authorized federation signing key."""
    domain: str
    key_id: str
    public_key_pem: str
    not_before: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    revoked: bool = False


class ServerTrustStore:
    """Explicit trust store; discovery never creates trust."""

    def __init__(self, records: Optional[list[ServerTrustRecord]] = None):
        if records is None:
            records = []
            try:
                configured = get_config().federation.trusted_keys
                records = [
                    ServerTrustRecord(
                        domain=item.domain,
                        key_id=item.key_id,
                        public_key_pem=item.public_key_pem,
                        not_before=item.not_before,
                        expires_at=item.expires_at,
                        revoked=item.revoked,
                    )
                    for item in configured
                ]
            except Exception:
                records = []
        self._records = {(r.domain, r.key_id): r for r in records}

    def add_key(
        self,
        domain: str,
        public_key_pem: str,
        *,
        not_before: Optional[datetime] = None,
        expires_at: Optional[datetime] = None,
        revoked: bool = False,
    ) -> ServerTrustRecord:
        key_id = public_key_id(public_key_pem)
        record = ServerTrustRecord(
            domain=domain,
            key_id=key_id,
            public_key_pem=public_key_pem,
            not_before=not_before,
            expires_at=expires_at,
            revoked=revoked,
        )
        self._records[(domain, key_id)] = record
        return record

    def revoke_key(self, domain: str, key_id: str) -> bool:
        record = self._records.get((domain, key_id))
        if not record:
            return False
        record.revoked = True
        return True

    def is_trusted(
        self,
        domain: str,
        key_id: str,
        public_key_pem: str,
        *,
        now: Optional[datetime] = None,
    ) -> bool:
        now = now or datetime.utcnow()
        record = self._records.get((domain, key_id))
        if record is None or record.revoked:
            return False
        if record.not_before and now < record.not_before:
            return False
        if record.expires_at and now >= record.expires_at:
            return False
        try:
            return (
                public_key_id(public_key_pem) == key_id
                and public_key_id(record.public_key_pem) == key_id
            )
        except Exception:
            return False


class ServerKeyManager:
    """Manages server key pairs for authentication."""
    
    def __init__(self):
        self._key_pair: Optional[ec.EllipticCurvePrivateKey] = None
        self._public_key_pem: Optional[str] = None
        self._load_or_generate_keys()
    
    def _load_or_generate_keys(self):
        """Load existing keys or generate new ones."""
        key_file = "./data/server_identity_key.pem"
        
        if os.path.exists(key_file):
            try:
                with open(key_file, 'rb') as f:
                    key_data = f.read()
                self._key_pair = serialization.load_pem_private_key(
                    key_data,
                    password=None,
                    backend=default_backend()
                )
                self._public_key_pem = self._key_pair.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()
                print("Loaded existing server identity keys")
                return
            except Exception as e:
                print(f"Error loading keys, generating new ones: {e}")
        
        # Generate new key pair
        self._key_pair = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self._public_key_pem = self._key_pair.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        # Save keys
        os.makedirs("./data", exist_ok=True)
        private_pem = self._key_pair.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(key_file, 'wb') as f:
            f.write(private_pem)
        print("Generated new server identity keys")
    
    def get_public_key_pem(self) -> str:
        """Get the server's public key in PEM format."""
        return self._public_key_pem

    def get_key_id(self) -> str:
        """Get the stable identifier for the server signing key."""
        return public_key_id(self._public_key_pem)
    
    def sign_data(self, data: str) -> str:
        """Sign data with the server's private key.
        
        Args:
            data: String data to sign
            
        Returns:
            Base64 encoded signature
        """
        if not self._key_pair:
            raise ValueError("No key pair available")
        
        message = data.encode('utf-8')
        signature = self._key_pair.sign(message, ec.ECDSA(hashes.SHA256()))
        
        # Convert signature to DER format and encode
        r, s = decode_dss_signature(signature)
        sig_der = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
        return base64.b64encode(sig_der).decode()
    
    def verify_signature(self, data: str, signature: str, public_key_pem: str) -> bool:
        """Verify a signature from another server.
        
        Args:
            data: Original data that was signed
            signature: Base64 encoded signature
            public_key_pem: PEM encoded public key
            
        Returns:
            True if signature is valid
        """
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode(),
                backend=default_backend()
            )
            
            sig_bytes = base64.b64decode(signature)
            
            # Reconstruct signature in DER format
            r = int.from_bytes(sig_bytes[:32], 'big')
            s = int.from_bytes(sig_bytes[32:64], 'big')
            signature_der = encode_dss_signature(r, s)
            
            public_key.verify(signature_der, data.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
            return True
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False


class ServerRegistry:
    """Registry of known federated servers with verification status."""
    
    def __init__(self):
        self._servers: Dict[str, ServerIdentity] = {}
    
    def register_server(
        self,
        domain: str,
        public_key_pem: str,
        signature: Optional[str] = None
    ) -> ServerIdentity:
        """Register a new federated server.
        
        Args:
            domain: Server domain
            public_key_pem: Server's public key
            signature: Optional signature to verify
            
        Returns:
            ServerIdentity object
        """
        identity = ServerIdentity(
            domain=domain,
            public_key_pem=public_key_pem,
            signature=signature,
            issued_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=365),
            is_verified=False
        )
        
        self._servers[domain] = identity
        return identity
    
    def get_server(self, domain: str) -> Optional[ServerIdentity]:
        """Get server identity."""
        return self._servers.get(domain)
    
    def is_verified(self, domain: str) -> bool:
        """Check if a server has been verified."""
        identity = self._servers.get(domain)
        return identity.is_verified if identity else False
    
    def mark_verified(self, domain: str) -> bool:
        """Mark a server as verified."""
        if domain in self._servers:
            self._servers[domain].is_verified = True
            return True
        return False


def create_authenticated_request(
    method: str,
    path: str,
    body: str,
    timestamp: Optional[int] = None
) -> dict:
    """Create an authenticated request to a federated server.
    
    Args:
        method: HTTP method (GET, POST, etc.)
        path: Request path
        body: Request body (empty string for GET)
        timestamp: Unix timestamp (defaults to current time)
        
    Returns:
        Dict with request headers including authentication
    """
    key_manager = get_key_manager()
    
    if timestamp is None:
        timestamp = int(time.time())
    
    request_id = secrets.token_urlsafe(24)
    key_id = key_manager.get_key_id()
    domain = get_config().server.domain
    payload = (
        f"{method}:{path}:{timestamp}:{request_id}:{domain}:{key_id}:"
        f"{hashlib.sha256(body.encode()).hexdigest()}"
    )
    
    signature = key_manager.sign_data(payload)
    
    return {
        "X-Server-Signature": signature,
        "X-Server-Key-ID": key_id,
        "X-Server-Timestamp": str(timestamp),
        "X-Server-Request-ID": request_id,
        "X-Server-Public-Key": key_manager.get_public_key_pem(),
        "X-Server-Domain": domain,
    }


def verify_authenticated_request(
    method: str,
    path: str,
    body: str,
    headers: dict,
    server_domain: Optional[str] = None
) -> bool:
    """Verify an authenticated request from a federated server.
    
    Args:
        method: HTTP method
        path: Request path
        body: Request body
        headers: Request headers
        server_domain: Expected server domain
        
    Returns:
        True if request is authenticated
    """
    # Extract headers
    signature = headers.get("X-Server-Signature")
    timestamp_str = headers.get("X-Server-Timestamp")
    request_id = headers.get("X-Server-Request-ID")
    public_key = headers.get("X-Server-Public-Key")
    key_id = headers.get("X-Server-Key-ID")
    domain = headers.get("X-Server-Domain")
    
    if not all([signature, timestamp_str, request_id, public_key, key_id, domain]):
        return False
        return False
    
    # Verify timestamp is recent (within 5 minutes)
    try:
        timestamp = int(timestamp_str)
        current_time = int(time.time())
        if abs(current_time - timestamp) > REQUEST_FRESHNESS_SECONDS:
            return False
    except ValueError:
        return False
    
    # The claimed domain is an identity label; authorization comes from
    # the explicit domain -> key trust binding.
    if server_domain and domain != server_domain:
        return False

    if not get_trust_store().is_trusted(domain, key_id, public_key):
        return False
    
    payload = (
        f"{method}:{path}:{timestamp}:{request_id}:{domain}:{key_id}:"
        f"{hashlib.sha256(body.encode()).hexdigest()}"
    )
    
    try:
        public_key_obj = serialization.load_pem_public_key(
            public_key.encode(),
            backend=default_backend(),
        )
        sig_bytes = base64.b64decode(signature, validate=True)
        if len(sig_bytes) != 64:
            return False
        r = int.from_bytes(sig_bytes[:32], "big")
        s = int.from_bytes(sig_bytes[32:], "big")
        signature_der = encode_dss_signature(r, s)
        public_key_obj.verify(
            signature_der,
            payload.encode("utf-8"),
            ec.ECDSA(hashes.SHA256()),
        )
    except Exception:
        return False

    now = int(time.time())
    cache_key = (domain, key_id, request_id)
    with _seen_requests_lock:
        expired = [
            key for key, seen_at in _seen_requests.items()
            if now - seen_at > REQUEST_FRESHNESS_SECONDS
        ]
        for key in expired:
            _seen_requests.pop(key, None)
        if cache_key in _seen_requests:
            return False
        _seen_requests[cache_key] = now

    return True


# Global instances
_key_manager: Optional[ServerKeyManager] = None
_server_registry: Optional[ServerRegistry] = None
_trust_store: Optional[ServerTrustStore] = None
_seen_requests: Dict[tuple[str, str, str], int] = {}
_seen_requests_lock = threading.Lock()
REQUEST_FRESHNESS_SECONDS = 300


def get_key_manager() -> ServerKeyManager:
    """Get the global key manager instance."""
    global _key_manager
    if _key_manager is None:
        _key_manager = ServerKeyManager()
    return _key_manager


def get_trust_store() -> ServerTrustStore:
    """Return the configured federation trust store."""
    global _trust_store
    if _trust_store is None:
        _trust_store = ServerTrustStore()
    return _trust_store


def reset_trust_store() -> None:
    """Reset the trust store singleton."""
    global _trust_store
    _trust_store = None


def get_server_registry() -> ServerRegistry:
    """Get the global server registry instance."""
    global _server_registry
    if _server_registry is None:
        _server_registry = ServerRegistry()
    return _server_registry


def get_config():
    """Get config (lazy import to avoid circular deps)."""
    from decemsg.core.config import get_config
    return get_config()
