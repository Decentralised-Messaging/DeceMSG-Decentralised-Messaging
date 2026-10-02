"""DeceMSG configuration module."""
import os
from pathlib import Path
from typing import List, Optional
from datetime import datetime
from functools import lru_cache

import yaml
from pydantic import BaseModel
from pydantic_settings import BaseSettings


class ServerConfig(BaseModel):
    domain: str = "localhost"
    host: str = "0.0.0.0"
    port: int = 8000
    title: str = "DeceMSG Server"


class DatabaseConfig(BaseModel):
    type: str = "sqlite"
    path: str = "./data/decemsg.db"


class AuthConfig(BaseModel):
    allow_public_registration: bool = False
    allow_user_group_creation: bool = True
    jwt_secret: str = "change-me-in-production-use-strong-random-key"
    jwt_expiry_hours: int = 24


class MessagingConfig(BaseModel):
    default_keep_history: bool = True
    max_file_size_mb: int = 10
    allowed_file_types: List[str] = [".jpg", ".png", ".gif", ".pdf", ".doc", ".docx", ".txt"]


class FederationTrustedKey(BaseModel):
    """Explicitly trusted federation signing key for a domain."""

    domain: str
    key_id: str
    public_key_pem: str
    not_before: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    revoked: bool = False


class FederationConfig(BaseModel):
    enabled: bool = True
    discovery_mode: str = "dns"
    trust_model: str = "explicit_key_pinning"
    trusted_keys: List[FederationTrustedKey] = []


class RateLimitConfig(BaseModel):
    enabled: bool = True
    login_rate: str = "5/minute"
    api_rate: str = "100/minute"
    burst_size: int = 10


class AppConfig(BaseSettings):
    server: ServerConfig = ServerConfig()
    database: DatabaseConfig = DatabaseConfig()
    auth: AuthConfig = AuthConfig()
    messaging: MessagingConfig = MessagingConfig()
    federation: FederationConfig = FederationConfig()
    rate_limit: RateLimitConfig = RateLimitConfig()

    @classmethod
    def load_from_yaml(cls, config_path: str = "config.yaml") -> "AppConfig":
        """Load configuration from YAML file."""
        path = Path(config_path)
        if not path.exists():
            # Try parent directories
            current = Path.cwd()
            for parent in [current] + list(current.parents):
                candidate = parent / "config.yaml"
                if candidate.exists():
                    path = candidate
                    break
        
        if path.exists():
            with open(path, "r") as f:
                data = yaml.safe_load(f)
                return cls(**data) if data else cls()
        return cls()

    def save_to_yaml(self, config_path: str = "config.yaml"):
        """Save configuration to YAML file."""
        data = {
            "server": self.server.model_dump(),
            "database": self.database.model_dump(),
            "auth": self.auth.model_dump(),
            "messaging": self.messaging.model_dump(),
            "federation": self.federation.model_dump(),
            "rate_limit": self.rate_limit.model_dump(),
        }
        with open(config_path, "w") as f:
            yaml.dump(data, f, default_flow_style=False)


@lru_cache()
def get_config() -> AppConfig:
    """Get cached configuration instance."""
    config_path = os.environ.get("DECEMSG_CONFIG", "config.yaml")
    return AppConfig.load_from_yaml(config_path)


def reset_config():
    """Reset cached configuration."""
    get_config.cache_clear()
