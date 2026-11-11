"""
CyberRisk-Guidewire-Connector (CRGC)
Core Security & Authentication Module
Implements standard HMAC-SHA256 JWT tokens and PBKDF2 password hashing.
"""

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel

from config.settings import Settings, get_settings

logger = logging.getLogger("crgc.security")

# OAuth2 scheme for Swagger UI & Authorization header parsing
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v1/auth/token",
    auto_error=False,
)

# Ephemeral development fallback secret (never static, never used in production)
_DEV_FALLBACK_SECRET = secrets.token_urlsafe(32)


class TokenData(BaseModel):
    username: str
    role: str
    full_name: str
    exp: int


class UserProfile(BaseModel):
    username: str
    role: str
    full_name: str
    is_active: bool = True


# ==============================================================================
# Password Hashing & Verification (PBKDF2-HMAC-SHA256)
# ==============================================================================
def hash_password(password: str) -> str:
    """Hashes a plaintext password using PBKDF2-HMAC-SHA256 with a unique salt."""
    salt = secrets.token_hex(16)
    iterations = 100_000
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
    )
    return f"pbkdf2_sha256${iterations}${salt}${derived.hex()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plaintext password against a stored PBKDF2 hash using timing-safe comparison."""
    try:
        parts = hashed_password.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False
        iterations = int(parts[1])
        salt = parts[2]
        expected_hex = parts[3]

        derived = hashlib.pbkdf2_hmac(
            "sha256",
            plain_password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations,
        )
        return hmac.compare_digest(derived.hex(), expected_hex)
    except Exception as e:
        logger.warning("Password verification failed with error: %s", str(e))
        return False


# ==============================================================================
# Standard HMAC-SHA256 JWT Token Generation & Verification
# ==============================================================================
def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data.encode("utf-8"))


def get_jwt_secret_key(settings: Optional[Settings] = None) -> bytes:
    """Returns the effective secret key bytes, rejecting weak keys in production."""
    cfg = settings or get_settings()
    secret = cfg.jwt_secret_key.strip() if cfg.jwt_secret_key else ""
    if not secret:
        if cfg.app_env in ("development", "test"):
            secret = _DEV_FALLBACK_SECRET
        else:
            raise RuntimeError("CRGC FATAL: JWT_SECRET_KEY must be configured in production environment.")
    return secret.encode("utf-8")


def create_access_token(
    data: dict[str, Any],
    expires_delta: Optional[timedelta] = None,
    settings: Optional[Settings] = None,
) -> str:
    """Generates an RFC 7519 compliant HMAC-SHA256 JWT access token."""
    cfg = settings or get_settings()
    now_ts = int(time.time())
    if expires_delta:
        exp_ts = now_ts + int(expires_delta.total_seconds())
    else:
        exp_ts = now_ts + (cfg.jwt_expiration_minutes * 60)

    header = {"alg": cfg.jwt_algorithm, "typ": "JWT"}
    payload = {**data, "iat": now_ts, "exp": exp_ts}

    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")

    secret_key = get_jwt_secret_key(cfg)
    signature = hmac.new(secret_key, signing_input, hashlib.sha256).digest()
    signature_b64 = _b64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{signature_b64}"


def decode_access_token(
    token: str,
    settings: Optional[Settings] = None,
) -> dict[str, Any]:
    """Validates the cryptographic signature and expiration of an access token."""
    cfg = settings or get_settings()
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Token must contain exactly 3 segments")
        header_b64, payload_b64, signature_b64 = parts

        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
        secret_key = get_jwt_secret_key(cfg)
        expected_sig = hmac.new(secret_key, signing_input, hashlib.sha256).digest()
        actual_sig = _b64url_decode(signature_b64)

        if not hmac.compare_digest(expected_sig, actual_sig):
            raise ValueError("Cryptographic signature mismatch")

        payload_bytes = _b64url_decode(payload_b64)
        payload = json.loads(payload_bytes.decode("utf-8"))

        now_ts = int(time.time())
        if "exp" in payload and payload["exp"] < now_ts:
            raise ValueError("Token has expired")

        return payload
    except Exception as e:
        logger.debug("Access token decoding failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Could not validate credentials: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ==============================================================================
# Demo User Registry (Development Demonstration Only)
# ==============================================================================
_CACHED_DEMO_HASHES: dict[str, tuple[str, str]] = {}


def get_demo_users(settings: Optional[Settings] = None) -> dict[str, dict[str, Any]]:
    """
    Returns registered demo users strictly for development and academic demonstrations.
    Disabled automatically in staging/production environments.
    """
    cfg = settings or get_settings()
    if cfg.app_env not in ("development", "test") or not cfg.demo_auth_enabled:
        return {}

    underwriter_pw = cfg.demo_underwriter_password.strip() if cfg.demo_underwriter_password else ""
    admin_pw = cfg.demo_admin_password.strip() if cfg.demo_admin_password else ""

    users: dict[str, dict[str, Any]] = {}
    for uname, role, full_name, raw_pw in [
        ("underwriter_demo", "underwriter", "Jane Doe (Senior Cyber Underwriter)", underwriter_pw),
        ("admin_demo", "admin", "CRGC System Administrator", admin_pw),
    ]:
        if not raw_pw:
            continue
        cached = _CACHED_DEMO_HASHES.get(uname)
        if not cached or cached[0] != raw_pw:
            _CACHED_DEMO_HASHES[uname] = (raw_pw, hash_password(raw_pw))
        users[uname] = {
            "username": uname,
            "full_name": full_name,
            "role": role,
            "password_hash": _CACHED_DEMO_HASHES[uname][1],
            "is_active": True,
        }
    return users


def authenticate_user(
    username: str,
    password: str,
    settings: Optional[Settings] = None,
) -> Optional[UserProfile]:
    """Authenticates a user against the demo registry."""
    users = get_demo_users(settings)
    user_record = users.get(username.strip())
    if not user_record:
        return None
    if not verify_password(password, user_record["password_hash"]):
        return None
    return UserProfile(
        username=user_record["username"],
        role=user_record["role"],
        full_name=user_record["full_name"],
        is_active=user_record["is_active"],
    )


# ==============================================================================
# FastAPI Current User Dependency
# ==============================================================================
async def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    settings: Settings = Depends(get_settings),
) -> UserProfile:
    """
    FastAPI dependency that extracts and validates the JWT Bearer token.
    Raises HTTP 401 Unauthorized if the token is missing or invalid.
    """
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token is required for this action. Please log in.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(token, settings=settings)
    username = payload.get("sub") or payload.get("username")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload is missing subject/username identifier.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return UserProfile(
        username=username,
        role=payload.get("role", "underwriter"),
        full_name=payload.get("full_name", username),
        is_active=True,
    )
