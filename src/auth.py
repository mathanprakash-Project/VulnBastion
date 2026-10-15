"""
VulnBastion / TawasolPay CyberSentinel — Authentication, RBAC & Rate Limiting
Enforces server-side API Key verification, role hierarchy, and sliding-window rate limits.
"""
import time
from collections import defaultdict
from typing import Dict, List, Optional
from fastapi import Depends, Header, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

from config import settings
from logger import logger

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


# ----------------------------- Models & Roles -----------------------------

ROLE_HIERARCHY = {
    "admin": 3,
    "analyst": 2,
    "viewer": 1,
}


class UserIdentity(BaseModel):
    api_key_id: str
    role: str = "viewer"
    is_authenticated: bool = True

    def has_role(self, required_role: str) -> bool:
        user_level = ROLE_HIERARCHY.get(self.role.lower(), 0)
        req_level = ROLE_HIERARCHY.get(required_role.lower(), 0)
        return user_level >= req_level


# ----------------------------- Rate Limiter -----------------------------

class SlidingWindowRateLimiter:
    """In-memory sliding window rate limiter per client key / IP."""

    def __init__(self, max_requests: int = 120, window_seconds: float = 60.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, List[float]] = defaultdict(list)

    def is_allowed(self, client_id: str) -> bool:
        now = time.time()
        window_start = now - self.window_seconds

        # Clean timestamps older than window
        self.requests[client_id] = [t for t in self.requests[client_id] if t > window_start]

        if len(self.requests[client_id]) >= self.max_requests:
            return False

        self.requests[client_id].append(now)
        return True

    def reset(self):
        self.requests.clear()


rate_limiter = SlidingWindowRateLimiter(max_requests=settings.RATE_LIMIT_PER_MINUTE)


# ----------------------------- Dependencies -----------------------------

def check_rate_limit(request: Request):
    """Enforces per-client sliding window rate limiting."""
    client_ip = request.client.host if request.client else "unknown"
    if not rate_limiter.is_allowed(client_ip):
        logger.warning(f"Rate limit exceeded for client: {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please retry after some time.",
            headers={"Retry-After": "60"},
        )


def get_current_user(
    api_key: Optional[str] = Security(api_key_header),
    auth_header: Optional[str] = Header(None, alias="Authorization"),
) -> UserIdentity:
    """
    Validates API key from X-API-Key or Bearer token.
    If REQUIRE_AUTH is False (default in dev), grants admin access seamlessly.
    """
    if not settings.REQUIRE_AUTH:
        # Development / permissive mode
        return UserIdentity(api_key_id="dev-bypass", role="admin", is_authenticated=True)

    extracted_key = None
    if api_key:
        extracted_key = api_key.strip()
    elif auth_header and auth_header.startswith("Bearer "):
        extracted_key = auth_header[7:].strip()

    if not extracted_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide 'X-API-Key' or 'Authorization: Bearer <key>' header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # Check key validity
    if extracted_key not in settings.API_KEYS:
        logger.warning(f"Rejected invalid API key: {extracted_key[:4]}***")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key provided.",
        )

    role = settings.API_KEYS[extracted_key]
    return UserIdentity(api_key_id=extracted_key[:8], role=role, is_authenticated=True)


def require_role(required_role: str):
    """Dependency factory checking if current user has the required role."""

    def _role_checker(user: UserIdentity = Depends(get_current_user)) -> UserIdentity:
        if not user.has_role(required_role):
            logger.warning(
                f"Forbidden access: User '{user.api_key_id}' with role '{user.role}' "
                f"attempted action requiring '{required_role}'"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Action requires '{required_role}' role or higher.",
            )
        return user

    return _role_checker

