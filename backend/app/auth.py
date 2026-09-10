from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from app.settings import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    ADMIN_PASSWORD_HASH,
    ADMIN_USERNAME,
    ALGORITHM,
    SECRET_KEY,
)

# ─── Config ─────────────────────────────────────────────────────────────────
INSECURE_SECRET_KEYS = {
    "",
    "changeme",
    "change-me",
    "fallback-insecure-key-change-in-production",
    "your-secret-key",
}

# ─── Crypto ──────────────────────────────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer()

# ─── Models ──────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    username: str

# ─── Helpers ──────────────────────────────────────────────────────────────────
def _safe_verify(plain: str, hashed: str) -> bool:
    # passlib/bcrypt 4.x raises ValueError on plain > 72 bytes, AND its
    # internal detect_wrap_bug self-test also calls verify() inside the
    # context global with whatever secret the caller supplied. Keep this
    # helper defensive so neither path can blow up the request.
    try:
        safe = plain[:72].encode("utf-8", errors="ignore").decode("utf-8")
        return pwd_context.verify(safe, hashed)
    except ValueError:
        return False


def verify_password(plain: str, hashed: str) -> bool:
    return _safe_verify(plain, hashed)


def validate_auth_configuration() -> None:
    if SECRET_KEY.lower() in INSECURE_SECRET_KEYS or len(SECRET_KEY) < 32:
        raise RuntimeError(
            "SECRET_KEY must be set to a unique value of at least 32 characters."
        )

    if not ADMIN_USERNAME:
        raise RuntimeError("ADMIN_USERNAME must be configured.")

    if not ADMIN_PASSWORD_HASH:
        raise RuntimeError("ADMIN_PASSWORD_HASH must be configured.")


# Warm up passlib/bcrypt at import time so the detect_wrap_bug self-test that
# runs inside pwd_context.verify() never surprises a live login request.
try:
    _warmup_hash = pwd_context.hash("warmup")
    _ = pwd_context.verify("warmup", _warmup_hash)
except Exception:
    pass

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def authenticate_user(username: str, password: str) -> Optional[dict]:
    """Validate username + password. Returns user dict or None."""
    if username != ADMIN_USERNAME:
        return None
    if not ADMIN_PASSWORD_HASH or not verify_password(password, ADMIN_PASSWORD_HASH):
        return None
    return {"username": username, "role": "admin"}

# ─── FastAPI Dependency ───────────────────────────────────────────────────────
def verify_token(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> dict:
    """
    FastAPI dependency injected into protected routes.
    Raises 401 if the token is missing, expired, or invalid.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Please log in.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        return {"username": username, "role": payload.get("role", "viewer")}
    except JWTError:
        raise credentials_exception
