"""
Unit tests for Authentication, RBAC, and Rate Limiting.
"""
import pytest
from fastapi import HTTPException
from auth import (
    ROLE_HIERARCHY,
    SlidingWindowRateLimiter,
    UserIdentity,
    get_current_user,
    require_role,
)
from config import settings


def test_user_identity_role_hierarchy():
    admin = UserIdentity(api_key_id="k-admin", role="admin")
    analyst = UserIdentity(api_key_id="k-analyst", role="analyst")
    viewer = UserIdentity(api_key_id="k-viewer", role="viewer")

    # Admin has all permissions
    assert admin.has_role("viewer") is True
    assert admin.has_role("analyst") is True
    assert admin.has_role("admin") is True

    # Analyst has analyst and viewer
    assert analyst.has_role("viewer") is True
    assert analyst.has_role("analyst") is True
    assert analyst.has_role("admin") is False

    # Viewer has only viewer
    assert viewer.has_role("viewer") is True
    assert viewer.has_role("analyst") is False
    assert viewer.has_role("admin") is False


def test_sliding_window_rate_limiter():
    limiter = SlidingWindowRateLimiter(max_requests=3, window_seconds=1.0)
    client_id = "test-client-1"

    # First 3 requests allowed
    assert limiter.is_allowed(client_id) is True
    assert limiter.is_allowed(client_id) is True
    assert limiter.is_allowed(client_id) is True

    # 4th request rejected
    assert limiter.is_allowed(client_id) is False

    # Another client is unaffected
    assert limiter.is_allowed("test-client-2") is True


def test_require_role_rejection():
    viewer = UserIdentity(api_key_id="k-viewer", role="viewer")
    admin_checker = require_role("admin")

    # Should raise HTTP 403 Forbidden for viewer
    with pytest.raises(HTTPException) as exc_info:
        admin_checker(viewer)

    assert exc_info.value.status_code == 403
    assert "Forbidden" in exc_info.value.detail

