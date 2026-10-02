"""DeceMSG authentication API endpoints."""
from datetime import datetime, timedelta
import base64
import binascii
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from slowapi import Limiter
from slowapi.util import get_remote_address

from decemsg.core.database import get_db
from decemsg.core.auth import (
    verify_password,
    get_password_hash,
    create_access_token,
    get_current_session,
    get_current_user,
    validate_login_device,
)
from decemsg.core.config import get_config
from decemsg.core.rate_limiter import limiter, get_login_rate_limit
from decemsg.models.user import User
from decemsg.models.session import UserSession
from decemsg.models.identity import UserIdentity
from decemsg.models.device import Device, DeviceStatus
from decemsg.models.recovery import IdentityRecoveryBackup

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


# Request/Response Models
class Token(BaseModel):
    """JWT token response."""
    access_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    """User creation request."""
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_]+$")
    display_name: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=6)
    domain: str | None = None


class UserLogin(BaseModel):
    """User login request."""
    username: str
    password: str


class UserResponse(BaseModel):
    """User response model."""
    id: str
    username: str
    display_name: str
    domain: str
    avatar_url: str | None
    created_at: str | None
    last_seen: str | None
    is_active: bool
    is_admin: bool

    class Config:
        from_attributes = True


class AuthConfigResponse(BaseModel):
    """Public authentication configuration (safe for anonymous clients)."""
    allow_public_registration: bool


@router.get("/config", response_model=AuthConfigResponse)
async def get_auth_config():
    """Get public authentication settings (no auth required)."""
    config = get_config()
    return AuthConfigResponse(
        allow_public_registration=config.auth.allow_public_registration,
    )


@router.post("/login", response_model=Token)
@limiter.limit(get_login_rate_limit())
async def login(
    request: Request,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: AsyncSession = Depends(get_db)
):
    """Authenticate user and return JWT token."""
    config = get_config()
    
    # Find user by username
    result = await db.execute(
        select(User).where(User.username == form_data.username)
    )
    user = result.scalar_one_or_none()
    
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated"
        )
    
    # Create a revocable server-side session and bind the JWT to it.
    access_token_expires = timedelta(hours=config.auth.jwt_expiry_hours)
    expires_at = datetime.utcnow() + access_token_expires
    requested_device_id = request.headers.get("X-Device-ID")
    device_id = await validate_login_device(
        db,
        user.id,
        requested_device_id,
    )

    session = UserSession(
        user_id=user.id,
        device_id=device_id,
        expires_at=expires_at,
        user_agent=request.headers.get("user-agent"),
        ip_address=request.client.host if request.client else None,
    )
    db.add(session)
    await db.flush()

    access_token = create_access_token(
        data={"sub": user.id, "sid": session.id},
        expires_delta=access_token_expires,
    )
    await db.commit()

    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/register", response_model=UserResponse)
@limiter.limit(get_login_rate_limit())
async def register(
    request: Request,
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db)
):
    """Register a new user (if public registration is enabled)."""
    config = get_config()
    
    if not config.auth.allow_public_registration:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Public registration is disabled. Contact an admin to create your account."
        )
    
    # Check if username already exists
    result = await db.execute(
        select(User).where(User.username == user_data.username)
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    # Create user
    domain = user_data.domain or config.server.domain
    user = User(
        username=user_data.username,
        display_name=user_data.display_name,
        password_hash=get_password_hash(user_data.password),
        domain=domain,
        is_admin=False,
    )
    
    db.add(user)
    await db.flush()
    db.add(UserIdentity(
        user_id=user.id,
        username=user.username,
        domain=user.domain,
    ))
    await db.commit()
    await db.refresh(user)
    
    return UserResponse(
        id=user.id,
        username=user.username,
        display_name=user.display_name,
        domain=user.domain,
        avatar_url=user.avatar_url,
        created_at=user.created_at.isoformat() if user.created_at else None,
        last_seen=user.last_seen.isoformat() if user.last_seen else None,
        is_active=user.is_active,
        is_admin=user.is_admin,
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
):
    """Get current authenticated user information."""
    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        display_name=current_user.display_name,
        domain=current_user.domain,
        avatar_url=current_user.avatar_url,
        created_at=current_user.created_at.isoformat() if current_user.created_at else None,
        last_seen=current_user.last_seen.isoformat() if current_user.last_seen else None,
        is_active=current_user.is_active,
        is_admin=current_user.is_admin,
    )


class PasswordChangeRequest(BaseModel):
    """Request for an authenticated password change."""
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=6)


@router.post("/change-password")
async def change_password(
    password_data: PasswordChangeRequest,
    current_user: User = Depends(get_current_user),
    current_session: UserSession = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    """Change the account password after step-up verification."""
    if current_session.user_id != current_user.id:
        raise HTTPException(status_code=401, detail="Invalid session")

    if not verify_password(password_data.current_password, current_user.password_hash):
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    if password_data.current_password == password_data.new_password:
        raise HTTPException(
            status_code=400,
            detail="New password must differ from the current password",
        )

    current_user.password_hash = get_password_hash(password_data.new_password)
    # Password changes intentionally do not revoke unrelated sessions or
    # rotate device/message encryption keys. Recovery-key re-encryption is
    # handled when the encrypted identity backup exists.
    await db.commit()

    return {"message": "Password changed successfully"}


@router.post("/logout")
async def logout(
    current_user: User = Depends(get_current_user),
    current_session: UserSession = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    """Revoke the current server-side session."""
    if current_session.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session")
    current_session.revoked_at = datetime.utcnow()
    await db.commit()
    return {"message": "Successfully logged out"}


class DeviceCreateRequest(BaseModel):
    """Enroll a new device cryptographic identity."""
    name: str = Field(..., min_length=1, max_length=100)
    platform: str = Field(..., min_length=1, max_length=50)
    public_identity_key: str = Field(..., min_length=32, max_length=4096)


class DeviceResponse(BaseModel):
    id: str
    name: str
    platform: str
    public_identity_key: str
    status: str
    created_at: str
    last_seen_at: str
    revoked_at: str | None


@router.post("/devices", response_model=DeviceResponse, status_code=status.HTTP_201_CREATED)
async def enroll_device(
    device_data: DeviceCreateRequest,
    current_user: User = Depends(get_current_user),
    current_session: UserSession = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    """Enroll a device and bind the current session to it."""
    if current_session.user_id != current_user.id:
        raise HTTPException(status_code=401, detail="Invalid session")

    device = Device(
        user_id=current_user.id,
        name=device_data.name,
        platform=device_data.platform,
        public_identity_key=device_data.public_identity_key,
    )
    db.add(device)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=409,
            detail="A device with this identity key is already registered",
        )

    current_session.device_id = device.id
    await db.commit()
    await db.refresh(device)

    return DeviceResponse(
        id=device.id,
        name=device.name,
        platform=device.platform,
        public_identity_key=device.public_identity_key,
        status=device.status.value,
        created_at=device.created_at.isoformat(),
        last_seen_at=device.last_seen_at.isoformat(),
        revoked_at=device.revoked_at.isoformat() if device.revoked_at else None,
    )


@router.get("/devices", response_model=list[DeviceResponse])
async def list_devices(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all enrolled devices without private key material."""
    result = await db.execute(
        select(Device)
        .where(Device.user_id == current_user.id)
        .order_by(Device.created_at.desc())
    )
    devices = result.scalars().all()
    return [
        DeviceResponse(
            id=device.id,
            name=device.name,
            platform=device.platform,
            public_identity_key=device.public_identity_key,
            status=device.status.value,
            created_at=device.created_at.isoformat(),
            last_seen_at=device.last_seen_at.isoformat(),
            revoked_at=device.revoked_at.isoformat() if device.revoked_at else None,
        )
        for device in devices
    ]


@router.delete("/devices/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_device(
    device_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Revoke one device and all sessions bound to it."""
    result = await db.execute(
        select(Device).where(
            Device.id == device_id,
            Device.user_id == current_user.id,
        )
    )
    device = result.scalar_one_or_none()
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")

    device.status = DeviceStatus.REVOKED
    device.revoked_at = datetime.utcnow()

    session_result = await db.execute(
        select(UserSession).where(
            UserSession.device_id == device.id,
            UserSession.revoked_at.is_(None),
        )
    )
    for session in session_result.scalars().all():
        session.revoked_at = datetime.utcnow()

    # Force a fresh Megolm room epoch for future messages so the revoked
    # device's previously received room key cannot decrypt new ciphertext.
    from decemsg.api.crypto import rotate_crypto_rooms_for_user
    await rotate_crypto_rooms_for_user(current_user.id, db)

    await db.commit()


class RecoveryBackupRequest(BaseModel):
    """Opaque client-encrypted identity backup envelope."""
    version: int = Field(..., ge=1)
    kdf_algorithm: str = Field(..., min_length=1, max_length=32)
    kdf_memory_kib: int = Field(..., ge=19456, le=1024 * 1024)
    kdf_iterations: int = Field(..., ge=2, le=20)
    kdf_parallelism: int = Field(..., ge=1, le=8)
    kdf_salt: str = Field(..., min_length=22, max_length=256)
    encryption_algorithm: str = Field(..., min_length=1, max_length=64)
    encryption_nonce: str = Field(..., min_length=16, max_length=256)
    ciphertext: str = Field(..., min_length=32, max_length=1_000_000)


def _validate_recovery_b64(value: str, field_name: str, min_bytes: int) -> None:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise HTTPException(status_code=400, detail=f"Invalid {field_name}")
    if len(decoded) < min_bytes:
        raise HTTPException(status_code=400, detail=f"Invalid {field_name}")


@router.put("/recovery/backup")
async def put_recovery_backup(
    backup_data: RecoveryBackupRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Store or replace an opaque client-encrypted identity backup."""
    if backup_data.kdf_algorithm.lower() != "argon2id":
        raise HTTPException(status_code=400, detail="Recovery backup must use Argon2id")
    if backup_data.encryption_algorithm.upper() not in {"AES-256-GCM", "XCHACHA20-POLY1305"}:
        raise HTTPException(status_code=400, detail="Unsupported recovery encryption algorithm")

    _validate_recovery_b64(backup_data.kdf_salt, "KDF salt", 16)
    _validate_recovery_b64(backup_data.encryption_nonce, "encryption nonce", 12)
    _validate_recovery_b64(backup_data.ciphertext, "ciphertext", 32)

    result = await db.execute(
        select(IdentityRecoveryBackup).where(
            IdentityRecoveryBackup.user_id == current_user.id
        )
    )
    backup = result.scalar_one_or_none()
    if backup is None:
        backup = IdentityRecoveryBackup(user_id=current_user.id)
        db.add(backup)

    backup.version = backup_data.version
    backup.kdf_algorithm = backup_data.kdf_algorithm.lower()
    backup.kdf_memory_kib = backup_data.kdf_memory_kib
    backup.kdf_iterations = backup_data.kdf_iterations
    backup.kdf_parallelism = backup_data.kdf_parallelism
    backup.kdf_salt = backup_data.kdf_salt
    backup.encryption_algorithm = backup_data.encryption_algorithm.upper()
    backup.encryption_nonce = backup_data.encryption_nonce
    backup.ciphertext = backup_data.ciphertext
    backup.updated_at = datetime.utcnow()

    await db.commit()
    return {"status": "stored", "version": backup.version}


@router.get("/recovery/backup")
async def get_recovery_backup(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieve only the opaque encrypted recovery backup."""
    result = await db.execute(
        select(IdentityRecoveryBackup).where(
            IdentityRecoveryBackup.user_id == current_user.id
        )
    )
    backup = result.scalar_one_or_none()
    if backup is None:
        raise HTTPException(status_code=404, detail="Recovery backup not found")

    return {
        "version": backup.version,
        "kdf_algorithm": backup.kdf_algorithm,
        "kdf_memory_kib": backup.kdf_memory_kib,
        "kdf_iterations": backup.kdf_iterations,
        "kdf_parallelism": backup.kdf_parallelism,
        "kdf_salt": backup.kdf_salt,
        "encryption_algorithm": backup.encryption_algorithm,
        "encryption_nonce": backup.encryption_nonce,
        "ciphertext": backup.ciphertext,
        "updated_at": backup.updated_at.isoformat(),
    }


@router.get("/sessions")
async def list_sessions(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List active sessions without exposing bearer credentials."""
    result = await db.execute(
        select(UserSession)
        .where(
            UserSession.user_id == current_user.id,
            UserSession.revoked_at.is_(None),
            UserSession.expires_at > datetime.utcnow(),
        )
        .order_by(UserSession.created_at.desc())
    )
    sessions = result.scalars().all()
    return {
        "sessions": [
            {
                "id": session.id,
                "device_id": session.device_id,
                "created_at": session.created_at.isoformat(),
                "expires_at": session.expires_at.isoformat(),
                "last_seen_at": session.last_seen_at.isoformat(),
                "user_agent": session.user_agent,
                "ip_address": session.ip_address,
            }
            for session in sessions
        ]
    }


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_session(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Revoke one of the current user's sessions."""
    result = await db.execute(
        select(UserSession).where(
            UserSession.id == session_id,
            UserSession.user_id == current_user.id,
        )
    )
    session = result.scalar_one_or_none()
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.revoked_at is None:
        session.revoked_at = datetime.utcnow()
        await db.commit()
