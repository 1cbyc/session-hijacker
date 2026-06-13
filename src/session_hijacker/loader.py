from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from session_hijacker.models import BrowserSessionExport, CookieRecord


class SessionLoader:
    """Parse cookies/tokens from browser exports and raw captures."""

    @classmethod
    def from_file(cls, path: str | Path) -> BrowserSessionExport:
        raw = Path(path).read_text(encoding="utf-8")
        return cls.from_json(raw)

    @classmethod
    def from_json(cls, raw: str | bytes) -> BrowserSessionExport:
        data = json.loads(raw)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BrowserSessionExport:
        if "base_url" not in data:
            raise ValueError("Session export must include base_url")

        cookies = cls._parse_cookies(data.get("cookies", []))
        local_storage = cls._stringify_kv(data.get("local_storage", {}))
        session_storage = cls._stringify_kv(data.get("session_storage", {}))
        extra_headers = cls._stringify_kv(data.get("extra_headers", {}))

        return BrowserSessionExport(
            base_url=data["base_url"],
            cookies=cookies,
            local_storage=local_storage,
            session_storage=session_storage,
            extra_headers=extra_headers,
            bearer_token_key=data.get("bearer_token_key"),
        )

    @classmethod
    def from_cookie_header(
        cls,
        base_url: str,
        cookie_header: str,
        *,
        local_storage: dict[str, str] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> BrowserSessionExport:
        cookies: list[CookieRecord] = []
        domain = urlparse(base_url).hostname

        for part in cookie_header.split(";"):
            part = part.strip()
            if not part or "=" not in part:
                continue
            name, value = part.split("=", 1)
            cookies.append(
                CookieRecord(name=name.strip(), value=value.strip(), domain=domain)
            )

        return BrowserSessionExport(
            base_url=base_url,
            cookies=cookies,
            local_storage=local_storage or {},
            extra_headers=extra_headers or {},
        )

    @staticmethod
    def _parse_cookies(raw: Any) -> list[CookieRecord]:
        if isinstance(raw, dict):
            return [
                CookieRecord(name=str(k), value=str(v)) for k, v in raw.items()
            ]

        if not isinstance(raw, list):
            raise ValueError("cookies must be a list or dict")

        cookies: list[CookieRecord] = []
        for item in raw:
            if isinstance(item, str):
                if "=" not in item:
                    continue
                name, value = item.split("=", 1)
                cookies.append(CookieRecord(name=name.strip(), value=value.strip()))
                continue

            if not isinstance(item, dict) or "name" not in item or "value" not in item:
                raise ValueError("Each cookie entry needs name and value")

            cookies.append(
                CookieRecord(
                    name=str(item["name"]),
                    value=str(item["value"]),
                    domain=item.get("domain"),
                    path=item.get("path", "/"),
                    expires=item.get("expires") or item.get("expirationDate"),
                    secure=bool(item.get("secure", False)),
                    http_only=bool(item.get("httpOnly", item.get("http_only", False))),
                    same_site=item.get("sameSite") or item.get("same_site"),
                )
            )
        return cookies

    @staticmethod
    def _stringify_kv(raw: Any) -> dict[str, str]:
        if not isinstance(raw, dict):
            return {}
        return {str(k): str(v) for k, v in raw.items()}
