"""DeceMSG authentication module."""
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status, WebSocket
from fastapi.security import OAuth2PasswordBearer
import bcrypt
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from decemsg.core.config import get_config
from decemsg.core.database import get_db
from decemsg.models.session import UserSession
from decemsg.models.device import Device, DeviceStatus

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its stored bcrypt hash."""
    if not hashed_password:
        return False
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"), hashed_password.encode("utf-8")
        )
    except (ValueError, TypeError):
        return False


def get_password_hash(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(
        password.encode("utf-8"), bcrypt.gensalt(rounds=12)
    ).decode("utf-8")


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    config = get_config()
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=config.auth.jwt_expiry_hours)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode, 
        config.auth.jwt_secret, 
        algorithm="HS256"
    )
    return encoded_jwt


def decode_token(token: str) -> dict:
    """Decode and verify a JWT token."""
    config = get_config()
    try:
        payload = jwt.decode(
            token, 
            config.auth.jwt_secret, 
            algorithms=["HS256"]
        )
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def validate_login_device(
    db: AsyncSession,
    user_id: str,
    device_id: str | None,
) -> str | None:
    """Validate an optional device binding presented during login."""
    if not device_id:
        return None

    result = await db.execute(
        select(Device).where(
            Device.id == device_id,
            Device.user_id == user_id,
        )
    )
    device = result.scalar_one_or_none()
    if device is None or device.status != DeviceStatus.ACTIVE or device.revoked_at is not None:
        raise HTTPException(status_code=403, detail="Device is revoked or not registered")
    return device.id


async def get_current_session(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> UserSession:
    """Validate a JWT and its corresponding revocable server-side session."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_token(token)
        user_id = payload.get("sub")
        session_id = payload.get("sid")
        if not user_id or not session_id:
            raise credentials_exception
    except HTTPException:
        raise credentials_exception

    result = await db.execute(
        select(UserSession).where(
            UserSession.id == session_id,
            UserSession.user_id == user_id,
        )
    )
    session = result.scalar_one_or_none()
    if session is None:
        raise credentials_exception

    now = datetime.utcnow()
    if session.revoked_at is not None or session.expires_at <= now:
        raise credentials_exception

    session.last_seen_at = now
    return session


async def get_current_user(
    current_session: UserSession = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    """Get the active user represented by a non-revoked session."""
    from decemsg.models.user import User

    result = await db.execute(
        select(User).where(User.id == current_session.user_id)
    )
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated",
        )

    return user


async def get_current_admin_user(
    current_user = Depends(get_current_user)
) -> "User":
    """Get current user and verify they are an admin."""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user


class WebSocketAuth:
    """WebSocket authentication handler."""
    
    @staticmethod
    async def authenticate(websocket: WebSocket) -> Optional[dict]:
        """Authenticate WebSocket connection using token in query params."""
        token = websocket.query_params.get("token")
        if not token:
            return None
        
        try:
            payload = decode_token(token)
            return payload
        except HTTPException:
            return None
