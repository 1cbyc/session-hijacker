from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from session_hijacker.client import HijackedSession
from session_hijacker.exporter import SessionExporter
from session_hijacker.loader import SessionLoader
from session_hijacker.models import SessionStatus
from session_hijacker.verifier import SessionVerifier


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="session-hijacker",
        description=(
            "Load browser cookies/tokens into httpx and export authenticated "
            "JSON session objects for scraping workers."
        ),
    )
    parser.add_argument(
        "input",
        type=Path,
        help="Browser session export JSON (cookies, localStorage, tokens)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Write authenticated session JSON to this file",
    )
    parser.add_argument(
        "--probe",
        default="/",
        help="Path to GET for session verification (default: /)",
    )
    parser.add_argument(
        "--no-probe",
        action="store_true",
        help="Skip live HTTP probe; only check cookie expiry",
    )
    parser.add_argument(
        "--request",
        metavar="METHOD:PATH",
        help="Optional authenticated request, e.g. GET:/api/me",
    )
    parser.add_argument(
        "--fail-on-invalid",
        action="store_true",
        help="Exit 1 when session is expired or invalid",
    )
    return parser


def run_request(session: HijackedSession, spec: str):
    if ":" not in spec:
        print("error: --request must be METHOD:PATH", file=sys.stderr)
        return None

    method, path = spec.split(":", 1)
    method = method.upper().strip()
    path = path.strip()
    if not path.startswith("/"):
        path = f"/{path}"

    return session.request(method, path)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    exit_code = 0

    export = SessionLoader.from_file(args.input)

    with HijackedSession(export) as session:
        verifier = SessionVerifier(session, probe_path=args.probe)
        verification = verifier.verify(probe=not args.no_probe)

        if args.request:
            response = run_request(session, args.request)
            if response is None:
                return 2
            verification = verifier.verify_response(response)
            print(
                json.dumps(
                    {"status": response.status_code, "body": response.text},
                    indent=2,
                )
            )
            if response.status_code >= 400:
                exit_code = 1

        payload = SessionExporter.from_session(session, verification)
        rendered = json.dumps(payload.model_dump(), indent=2)

        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
            print(f"Wrote {args.output}", file=sys.stderr)
        elif not args.request:
            print(rendered)

        if args.fail_on_invalid and verification.status in {
            SessionStatus.EXPIRED,
            SessionStatus.INVALID,
        }:
            exit_code = 1

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
