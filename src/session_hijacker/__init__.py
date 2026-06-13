"""Raw HTTP session hijacker — browser cookies/tokens into httpx."""

from session_hijacker.client import HijackedSession
from session_hijacker.exporter import SessionExporter
from session_hijacker.loader import SessionLoader
from session_hijacker.models import (
    AuthenticatedSession,
    BrowserSessionExport,
    SessionStatus,
    VerificationResult,
)
from session_hijacker.verifier import SessionVerifier
from session_hijacker.worker import WorkerSession

__all__ = [
    "AuthenticatedSession",
    "BrowserSessionExport",
    "HijackedSession",
    "SessionExporter",
    "SessionLoader",
    "SessionStatus",
    "SessionVerifier",
    "VerificationResult",
    "WorkerSession",
]

__version__ = "0.1.0"
