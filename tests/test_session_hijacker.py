from __future__ import annotations

from datetime import datetime, timezone

import httpx
import pytest

from session_hijacker.client import HijackedSession
from session_hijacker.exporter import SessionExporter
from session_hijacker.loader import SessionLoader
from session_hijacker.models import BrowserSessionExport, CookieRecord, SessionStatus
from session_hijacker.verifier import SessionVerifier


def test_loader_parses_cookie_dict():
    export = SessionLoader.from_dict(
        {
            "base_url": "https://example.com",
            "cookies": {"sid": "secret", "pref": "dark"},
        }
    )
    assert len(export.cookies) == 2
    assert export.cookies[0].name in {"sid", "pref"}


def test_loader_parses_chrome_style_cookies():
    export = SessionLoader.from_dict(
        {
            "base_url": "https://example.com",
            "cookies": [
                {
                    "name": "session",
                    "value": "tok",
                    "domain": ".example.com",
                    "expirationDate": 1893456000,
                    "secure": True,
                    "httpOnly": True,
                }
            ],
        }
    )
    assert export.cookies[0].expires == 1893456000


def test_expired_cookie_detection():
    past = datetime(2020, 1, 1, tzinfo=timezone.utc).timestamp()
    cookies = [CookieRecord(name="sid", value="x", expires=past)]
    assert HijackedSession.expired_cookie_names(cookies) == ["sid"]


def test_verifier_flags_auth_failure():
    export = BrowserSessionExport(base_url="https://example.com")
    session = HijackedSession(export)
    verifier = SessionVerifier(session)

    response = httpx.Response(403, request=httpx.Request("GET", "https://example.com/"))
    result = verifier.verify_response(response)

    assert result.status == SessionStatus.INVALID
    assert result.auth_failure is True
    session.close()


def test_exporter_produces_worker_payload():
    export = BrowserSessionExport(
        base_url="https://api.example.com",
        cookies=[CookieRecord(name="sid", value="live")],
        local_storage={"access_token": "jwt-here"},
        extra_headers={"X-Trace": "1"},
    )
    session = HijackedSession(export)
    payload = SessionExporter.from_session(
        session,
        verification=None,
        worker_id="scraper-01",
    )

    assert payload.base_url == "https://api.example.com"
    assert payload.cookies == {"sid": "live"}
    assert payload.headers["Authorization"] == "Bearer jwt-here"
    assert payload.tokens["access_token"] == "jwt-here"
    assert payload.metadata["worker_id"] == "scraper-01"
    session.close()


def test_hijacked_session_get(httpx_mock):
    export = BrowserSessionExport(
        base_url="https://example.com",
        cookies=[CookieRecord(name="sid", value="abc")],
    )
    httpx_mock.add_response(url="https://example.com/api/me", json={"ok": True})

    with HijackedSession(export) as session:
        response = session.get("/api/me")
        assert response.status_code == 200
        assert response.json() == {"ok": True}

        request = httpx_mock.get_request()
        assert request.headers.get("cookie") == "sid=abc"
