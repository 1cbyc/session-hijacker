from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, HttpUrl


class SessionStatus(str, Enum):
    VALID = "valid"
    EXPIRED = "expired"
    INVALID = "invalid"
    UNKNOWN = "unknown"


class CookieRecord(BaseModel):
    name: str
    value: str
    domain: str | None = None
    path: str = "/"
    expires: float | None = None
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None


class BrowserSessionExport(BaseModel):
    """Raw capture from a live browser session."""

    base_url: HttpUrl
    cookies: list[CookieRecord] = Field(default_factory=list)
    local_storage: dict[str, str] = Field(default_factory=dict)
    session_storage: dict[str, str] = Field(default_factory=dict)
    extra_headers: dict[str, str] = Field(default_factory=dict)
    bearer_token_key: str | None = Field(
        default=None,
        description="localStorage/sessionStorage key holding a bearer token",
    )


class VerificationResult(BaseModel):
    status: SessionStatus
    http_status: int | None = None
    message: str = ""
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expired_cookies: list[str] = Field(default_factory=list)
    auth_failure: bool = False


class AuthenticatedSession(BaseModel):
    """Clean JSON session object for external scraping workers."""

    base_url: str
    cookies: dict[str, str]
    headers: dict[str, str]
    tokens: dict[str, str]
    metadata: dict[str, Any]

    model_config = {"extra": "forbid"}
