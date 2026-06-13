from __future__ import annotations

from datetime import datetime, timezone

import httpx

from session_hijacker.client import HijackedSession
from session_hijacker.models import SessionStatus, VerificationResult


class SessionVerifier:
    """Detect expired cookies and sudden auth closures (401/403)."""

    AUTH_FAILURE_CODES = frozenset({401, 403})

    def __init__(
        self,
        session: HijackedSession,
        *,
        probe_path: str = "/",
        success_codes: frozenset[int] | None = None,
    ) -> None:
        self.session = session
        self.probe_path = probe_path
        self.success_codes = success_codes or frozenset({200, 201, 202, 204})

    def verify(self, *, probe: bool = True) -> VerificationResult:
        expired = HijackedSession.expired_cookie_names(self.session.export.cookies)
        if expired:
            return VerificationResult(
                status=SessionStatus.EXPIRED,
                message=f"Expired cookies: {', '.join(expired)}",
                expired_cookies=expired,
            )

        if not probe:
            return VerificationResult(
                status=SessionStatus.UNKNOWN,
                message="Cookie expiry OK; probe skipped",
            )

        return self._probe()

    def verify_response(self, response: httpx.Response) -> VerificationResult:
        expired = HijackedSession.expired_cookie_names(self.session.export.cookies)
        if expired:
            return VerificationResult(
                status=SessionStatus.EXPIRED,
                http_status=response.status_code,
                message=f"Expired cookies: {', '.join(expired)}",
                expired_cookies=expired,
            )

        if response.status_code in self.AUTH_FAILURE_CODES:
            return VerificationResult(
                status=SessionStatus.INVALID,
                http_status=response.status_code,
                message=f"Auth failure: HTTP {response.status_code}",
                auth_failure=True,
            )

        if response.status_code not in self.success_codes:
            return VerificationResult(
                status=SessionStatus.UNKNOWN,
                http_status=response.status_code,
                message=f"Unexpected HTTP {response.status_code}",
            )

        return VerificationResult(
            status=SessionStatus.VALID,
            http_status=response.status_code,
            message="Session verified",
        )

    def _probe(self) -> VerificationResult:
        try:
            response = self.session.get(self.probe_path)
        except httpx.HTTPError as exc:
            return VerificationResult(
                status=SessionStatus.UNKNOWN,
                message=f"Probe failed: {exc}",
            )

        return self.verify_response(response)

    @staticmethod
    def is_auth_failure(response: httpx.Response) -> bool:
        return response.status_code in SessionVerifier.AUTH_FAILURE_CODES

    @staticmethod
    def utcnow() -> datetime:
        return datetime.now(timezone.utc)
