# Session Hijacker

Load cookies and localStorage tokens from a live browser session into **httpx**, verify auth state, and export clean JSON for downstream scraping workers — no browser window required.

## Quick start

```bash
pip install -e ".[dev]"
```

Export session state from your browser (DevTools, extension, or manual JSON) and run:

```bash
session-hijacker examples/browser_session.json -o authenticated_session.json --probe /cookies
```

## Input format

```json
{
  "base_url": "https://target.example",
  "cookies": [
    {"name": "session_id", "value": "...", "domain": "target.example", "path": "/"}
  ],
  "local_storage": {
    "access_token": "eyJ..."
  },
  "session_storage": {},
  "extra_headers": {},
  "bearer_token_key": "access_token"
}
```

You can also pass cookies as a flat object (`{"sid": "..."}`) or a raw `Cookie` header via `SessionLoader.from_cookie_header()`.

## Python API

```python
from session_hijacker import (
    HijackedSession,
    SessionExporter,
    SessionLoader,
    SessionVerifier,
)

export = SessionLoader.from_file("browser_session.json")

with HijackedSession(export) as session:
    verification = SessionVerifier(session, probe_path="/api/me").verify()
    payload = SessionExporter.from_session(session, verification)

    if verification.status.value == "valid":
        data = session.get("/api/data").json()
```

## Verification

- **Cookie expiry** — flags expired session cookies before any network call
- **Live probe** — optional GET to detect sudden **401/403** auth closures
- **Per-response checks** — `SessionVerifier.verify_response()` after each worker request

## Output

Exported JSON is worker-ready:

```json
{
  "base_url": "https://target.example",
  "cookies": {"session_id": "..."},
  "headers": {"Authorization": "Bearer ...", "User-Agent": "..."},
  "tokens": {"access_token": "..."},
  "metadata": {
    "status": "valid",
    "verified_at": "2026-06-13T12:00:00+00:00",
    "http_status": 200,
    "auth_failure": false,
    "expired_cookies": []
  }
}
```

## Tests

```bash
pytest
```
