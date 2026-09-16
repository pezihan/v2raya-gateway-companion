import hmac
import hashlib
import secrets
from typing import Optional
from pydantic import BaseModel
from app.config import settings

class LoginRequest(BaseModel):
    password: str

def generate_auth_token(password: str) -> str:
    """Generates deterministic HMAC SHA256 token for valid password session"""
    if not password:
        return ""
    return hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        password.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

def verify_token(token: Optional[str]) -> bool:
    """Verifies session token against current password"""
    if not settings.AUTH_PASSWORD:
        return True
    if not token:
        return False
    expected = generate_auth_token(settings.AUTH_PASSWORD)
    return secrets.compare_digest(token.strip(), expected)

def verify_password(input_password: str) -> bool:
    """Verifies raw password against configured password"""
    if not settings.AUTH_PASSWORD:
        return True
    if not input_password:
        return False
    return secrets.compare_digest(input_password.strip(), settings.AUTH_PASSWORD.strip())
