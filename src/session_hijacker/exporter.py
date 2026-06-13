from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from session_hijacker.client import HijackedSession
from session_hijacker.models import AuthenticatedSession, SessionStatus, VerificationResult


class SessionExporter:
    """Export clean authenticated JSON for downstream scraping workers."""

    @classmethod
    def from_session(
        cls,
        session: HijackedSession,
        verification: VerificationResult | None = None,
        *,
        worker_id: str | None = None,
        extra_metadata: dict[str, Any] | None = None,
    ) -> AuthenticatedSession:
        metadata: dict[str, Any] = {
            "status": (verification.status if verification else SessionStatus.UNKNOWN).value,
            "verified_at": (
                verification.checked_at.isoformat()
                if verification
                else None
            ),
            "http_status": verification.http_status if verification else None,
            "message": verification.message if verification else "",
            "auth_failure": verification.auth_failure if verification else False,
            "expired_cookies": verification.expired_cookies if verification else [],
        }
        if worker_id:
            metadata["worker_id"] = worker_id
        if extra_metadata:
            metadata.update(extra_metadata)

        return AuthenticatedSession(
            base_url=session.base_url,
            cookies={c.name: c.value for c in session.export.cookies},
            headers=session.build_headers(),
            tokens=session.build_tokens(),
            metadata=metadata,
        )

    @classmethod
    def to_json(
        cls,
        session: HijackedSession,
        verification: VerificationResult | None = None,
        *,
        indent: int | None = 2,
        **kwargs: Any,
    ) -> str:
        payload = cls.from_session(session, verification, **kwargs)
        return json.dumps(payload.model_dump(), indent=indent)

    @classmethod
    def write_file(
        cls,
        path: str | Path,
        session: HijackedSession,
        verification: VerificationResult | None = None,
        **kwargs: Any,
    ) -> Path:
        out = Path(path)
        out.write_text(
            cls.to_json(session, verification, **kwargs),
            encoding="utf-8",
        )
        return out
