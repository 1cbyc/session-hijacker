from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

from session_hijacker.models import AuthenticatedSession, SessionStatus


class WorkerSession:
    """Rehydrate an exported authenticated session for scraping workers."""

    def __init__(
        self,
        payload: AuthenticatedSession,
        *,
        timeout: float = 30.0,
        follow_redirects: bool = True,
    ) -> None:
        self.payload = payload
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self._client: httpx.Client | None = None

    @classmethod
    def from_file(cls, path: str | Path, **kwargs: Any) -> WorkerSession:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(data, **kwargs)

    @classmethod
    def from_dict(cls, data: dict[str, Any], **kwargs: Any) -> WorkerSession:
        return cls(AuthenticatedSession.model_validate(data), **kwargs)

    @property
    def is_valid(self) -> bool:
        return self.payload.metadata.get("status") == SessionStatus.VALID.value

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                base_url=self.payload.base_url.rstrip("/"),
                headers=self.payload.headers,
                cookies=self.payload.cookies,
                timeout=self.timeout,
                follow_redirects=self.follow_redirects,
            )
        return self._client

    def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        return self.client.request(method, url, **kwargs)

    def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.client.get(url, **kwargs)

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> WorkerSession:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
