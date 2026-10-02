"""HTTP API for the on-board parameter multi-version serialisation audit.

Endpoints
---------
GET  /healthz                 -> trivial health probe (Compose healthcheck)
GET  /                        -> the audit console page (static/index.html)
POST /api/audits              -> freeze + analyse a payload
GET  /api/audits/<audit_id>   -> fetch a frozen verdict
GET  /api/audits              -> list frozen audit ids
"""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mvscc import PayloadError, build_analysis  # noqa: E402
from store import ConflictError, FrozenStore  # noqa: E402

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


class AuditHandler(BaseHTTPRequestHandler):
    server_version = "MVSCC-Audit/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

    # ------------------------------------------------------------------
    def _send_json(self, status, body, extra_headers=None):
        data = json.dumps(body, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for key, value in extra_headers or []:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def _send_html(self, text):
        data = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # ------------------------------------------------------------------
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            self._send_json(200, {"status": "ok"})
            return
        if path == "/api/audits":
            self._send_json(200, {"audit_ids": self.server.store.ids()})
            return
        if path.startswith("/api/audits/"):
            audit_id = path[len("/api/audits/") :]
            if "/" in audit_id or not audit_id:
                self._send_json(404, {"error": "NOT_FOUND"})
                return
            record = self.server.store.get(audit_id)
            if record is None:
                self._send_json(404, {"error": "AUDIT_NOT_FOUND", "audit_id": audit_id})
                return
            self._send_json(200, record["verdict"])
            return
        if path in ("/", "/index.html"):
            self._serve_index()
            return
        self._send_json(404, {"error": "NOT_FOUND"})

    def _serve_index(self):
        index_path = STATIC_DIR / "index.html"
        try:
            text = index_path.read_text(encoding="utf-8")
        except OSError:
            self._send_json(500, {"error": "CONSOLE_MISSING"})
            return
        self._send_html(text)

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path != "/api/audits":
            self._send_json(404, {"error": "NOT_FOUND"})
            return

        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(400, {"error": "BAD_JSON", "message": "request body must be valid JSON"})
            return

        try:
            verdict = build_analysis(payload)
        except PayloadError as exc:
            self._send_json(400, {"error": "INVALID_PAYLOAD", "message": str(exc)})
            return
        except Exception as exc:  # never leak a stack trace as a 200
            sys.stderr.write("analysis failure: %r\n" % (exc,))
            self._send_json(500, {"error": "ANALYSIS_FAILED", "message": str(exc)})
            return

        # A read of a stale/impossible version is an input error: it is
        # reported (deterministically, so an identical retry yields the
        # identical diagnosis) but never frozen as an audit verdict.
        if verdict["status"] == "INVALID_READ":
            self._send_json(
                422,
                {
                    "error": "STALE_VERSION_READ",
                    "message": (
                        "at least one read did not observe the latest version "
                        "committed before its transaction started"
                    ),
                    "verdict": verdict,
                },
            )
            return

        try:
            stored, replayed = self.server.store.submit(payload, verdict)
        except ConflictError as exc:
            self._send_json(
                409,
                {
                    "error": "AUDIT_ID_CONFLICT",
                    "message": str(exc),
                    "audit_id": exc.audit_id,
                },
            )
            return

        self._send_json(
            200 if replayed else 201,
            stored,
            [("X-Audit-Replayed", "true" if replayed else "false")],
        )


def make_server(host: str, port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), AuditHandler)
    server.store = FrozenStore()
    return server


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    if argv:
        port = int(argv[0])
    server = make_server(host, port)
    sys.stderr.write("mvscc audit listening on http://%s:%d\n" % (host, port))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
