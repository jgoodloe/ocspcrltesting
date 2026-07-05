"""Password hashing, API-token hashing, and signed session cookies.

Kept dependency-light and side-effect free so it is easy to unit test.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Optional

from itsdangerous import BadSignature, SignatureExpired, TimestampSigner
from passlib.context import CryptContext

_pwd = CryptContext(schemes=["argon2"], deprecated="auto")

# API tokens are shown once and stored only as a SHA-256 hash. The token itself
# carries this prefix so it is recognisable and greppable in logs/configs.
TOKEN_PREFIX = "ocspt_"


# ---- local passwords (argon2id) -------------------------------------------


def hash_password(password: str) -> str:
    return _pwd.hash(password)


def verify_password(password: str, password_hash: Optional[str]) -> bool:
    if not password_hash:
        return False
    try:
        return _pwd.verify(password, password_hash)
    except Exception:
        return False


# ---- API tokens ------------------------------------------------------------


def generate_api_token() -> str:
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """SHA-256 hex of the raw token — the only form stored server-side. Fast
    (unlike a password hash) because the token has full entropy."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def looks_like_api_token(value: str) -> bool:
    return value.startswith(TOKEN_PREFIX)


# ---- signed session cookies ------------------------------------------------


def _signer(secret: str) -> TimestampSigner:
    return TimestampSigner(secret, salt="ocspweb.session")


def sign_session(secret: str, user_id: int) -> str:
    return _signer(secret).sign(str(user_id).encode("utf-8")).decode("utf-8")


def verify_session(secret: str, value: str, max_age_seconds: int) -> Optional[int]:
    """Return the user id from a valid, unexpired session cookie, else None."""
    try:
        raw = _signer(secret).unsign(value, max_age=max_age_seconds)
        return int(raw.decode("utf-8"))
    except (BadSignature, SignatureExpired, ValueError):
        return None


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
