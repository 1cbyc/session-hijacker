from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx

from session_hijacker.models import BrowserSessionExport, CookieRecord


class HijackedSession:
    """Lightweight httpx client preloaded with hijacked browser state."""

    def __init__(
        self,
        export: BrowserSessionExport,
        *,
        timeout: float = 30.0,
        follow_redirects: bool = True,
    ) -> None:
        self.export = export
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self._client: httpx.Client | None = None

    @property
    def base_url(self) -> str:
        return str(self.export.base_url).rstrip("/")

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                base_url=self.base_url,
                headers=self.build_headers(),
                cookies=self.build_cookie_jar(),
                timeout=self.timeout,
                follow_redirects=self.follow_redirects,
            )
        return self._client

    def build_cookie_jar(self) -> httpx.Cookies:
        default_domain = urlparse(self.base_url).hostname or ""
        jar = httpx.Cookies()
        for cookie in self.export.cookies:
            jar.set(
                cookie.name,
                cookie.value,
                domain=cookie.domain or default_domain,
                path=cookie.path,
            )
        return jar

    def build_headers(self) -> dict[str, str]:
        headers = dict(self.export.extra_headers)
        headers.setdefault(
            "User-Agent",
            "session-hijacker/0.1 (+httpx; authenticated replay)",
        )

        bearer = self._resolve_bearer_token()
        if bearer and "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {bearer}"

        return headers

    def build_tokens(self) -> dict[str, str]:
        tokens: dict[str, str] = {}
        tokens.update(self.export.local_storage)
        tokens.update(self.export.session_storage)
        return tokens

    def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        return self.client.request(method, url, **kwargs)

    def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.client.get(url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.client.post(url, **kwargs)

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> HijackedSession:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _resolve_bearer_token(self) -> str | None:
        key = self.export.bearer_token_key
        if not key:
            for candidate in ("access_token", "token", "authToken", "jwt"):
                if candidate in self.export.local_storage:
                    key = candidate
                    break
                if candidate in self.export.session_storage:
                    key = candidate
                    break
            else:
                return None

        return (
            self.export.local_storage.get(key)
            or self.export.session_storage.get(key)
        )

    @staticmethod
    def expired_cookie_names(
        cookies: list[CookieRecord],
        *,
        now: datetime | None = None,
    ) -> list[str]:
        now_ts = (now or datetime.now(timezone.utc)).timestamp()
        expired: list[str] = []
        for cookie in cookies:
            if cookie.expires is None:
                continue
            expires = cookie.expires
            if expires > 1e12:
                expires /= 1000
            if expires <= now_ts:
                expired.append(cookie.name)
        return expired
