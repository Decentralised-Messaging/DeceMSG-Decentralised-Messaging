"""DeceMSG API module."""
from decemsg.api.auth import router as auth_router
from decemsg.api.users import router as users_router
from decemsg.api.users import avatars_router
from decemsg.api.chats import router as chats_router
from decemsg.api.messages import router as messages_router
from decemsg.api.admin import router as admin_router
from decemsg.api.websocket import router as websocket_router, websocket_endpoint
from decemsg.api.crypto import router as crypto_router

__all__ = [
    "auth_router",
    "users_router",
    "avatars_router",
    "chats_router",
    "messages_router",
    "admin_router",
    "websocket_router",
    "websocket_endpoint",
    "crypto_router",
]
