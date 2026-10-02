"""End-to-end durability tests: restart a real HTTP server over the same
frozen-record log and assert replay, conflict, tail-drop and corrupt-record
health semantics."""

import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import _bootstrap  # noqa: F401
from server import make_server

SERIAL = {
    "audit_id": "restart-serial",
    "initial": {"x": 1},
    "transactions": [
        {"id": "T1", "start": 1, "commit": 3, "steps": [
            {"op": "write", "key": "x", "value": 2}]},
        {"id": "T2", "start": 4, "commit": 6, "steps": [
            {"op": "read", "key": "x",
             "observed": {"source": "txn", "writer": "T1"}},
            {"op": "write", "key": "x", "value": 3}]},
    ],
}
SKEW = {
    "audit_id": "restart-skew",
    "initial": {"x": 100, "y": 100},
    "transactions": [
        {"id": "T1", "start": 1, "commit": 5, "steps": [
            {"op": "read", "key": "x", "observed": "initial"},
            {"op": "write", "key": "y", "value": -100}]},
        {"id": "T2", "start": 2, "commit": 6, "steps": [
            {"op": "read", "key": "y", "observed": "initial"},
            {"op": "write", "key": "x", "value": -100}]},
    ],
}


class ServerHarness:
    def __init__(self, log_path):
        self.log_path = log_path
        self.server = make_server("127.0.0.1", 0, log_path)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()

    def request(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", data=data, method=method
        )
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                raw = resp.read().decode()
                return resp.status, dict(resp.headers), json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode()
            return exc.code, dict(exc.headers), json.loads(raw) if raw else None


class RestartDurabilityTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.log = os.path.join(self.dir, "audit.log")

    def _start(self):
        h = ServerHarness(self.log)
        self.addCleanup(h.stop)
        return h

    def test_verdict_conflict_and_replay_survive_restart(self):
        first = self._start()
        status, _, body = first.request("POST", "/api/audits", SERIAL)
        self.assertEqual(status, 201)
        self.assertEqual(body["serial_order"], ["T1", "T2"])
        first.request("POST", "/api/audits", SKEW)
        first.stop()

        # ---- service restart over the same durable log ----
        second = self._start()
        status, _, health = second.request("GET", "/healthz")
        self.assertEqual((status, health["status"]), (200, "ok"))

        status, _, fetched = second.request("GET", "/api/audits/restart-serial")
        self.assertEqual(status, 200)
        self.assertEqual(fetched, body)  # byte-for-byte the original conclusion

        status, headers, replay = second.request("POST", "/api/audits", SERIAL)
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-Audit-Replayed"), "true")
        self.assertEqual(replay, body)

        changed = json.loads(json.dumps(SERIAL))
        changed["initial"]["x"] = 999
        status, _, err = second.request("POST", "/api/audits", changed)
        self.assertEqual(status, 409)
        self.assertEqual(err["error"], "AUDIT_ID_CONFLICT")

        status, _, listing = second.request("GET", "/api/audits")
        self.assertEqual(status, 200)
        self.assertEqual(sorted(listing["audit_ids"]),
                         ["restart-serial", "restart-skew"])

    def test_unfinished_tail_after_crash_is_not_readable_after_restart(self):
        first = self._start()
        status, _, body = first.request("POST", "/api/audits", SERIAL)
        self.assertEqual(status, 201)
        first.stop()

        with open(self.log, "ab") as f:
            f.write(b'{"version":1,"audit_id":"lost-tail","fingerprint":"'
                    + b"0" * 64 + b'"')  # no trailing newline: uncommitted

        second = self._start()
        status, _, health = second.request("GET", "/healthz")
        self.assertEqual(status, 200)
        status, _, listing = second.request("GET", "/api/audits")
        self.assertEqual(listing["audit_ids"], ["restart-serial"])
        status, _, _ = second.request("GET", "/api/audits/lost-tail")
        self.assertEqual(status, 404)

    def test_corrupted_committed_record_fails_health_and_blocks_writes(self):
        first = self._start()
        first.request("POST", "/api/audits", SERIAL)
        first.stop()

        with open(self.log, "rb") as f:
            lines = f.read().splitlines()
        record = json.loads(lines[0])
        record["fingerprint"] = "f" * 64  # break checksum on a committed line
        lines[0] = json.dumps(record, separators=(",", ":")).encode()
        with open(self.log, "wb") as f:
            f.write(b"\n".join(lines) + b"\n")

        second = self._start()
        status, _, health = second.request("GET", "/healthz")
        self.assertEqual(status, 503)
        self.assertEqual(health["error"], "AUDIT_LOG_CORRUPT")

        # no verdict from a log that did not fully verify
        status, _, gone = second.request("GET", "/api/audits/restart-serial")
        self.assertEqual(status, 503)
        self.assertEqual(gone["error"], "AUDIT_LOG_CORRUPT")
        status, _, listing = second.request("GET", "/api/audits")
        self.assertEqual(status, 503)

        status, _, err = second.request("POST", "/api/audits", SKEW)
        self.assertEqual(status, 503)
        self.assertEqual(err["error"], "AUDIT_LOG_INTEGRITY")

        second.stop()
        # corruption on disk is untouched by the refused write
        third = self._start()
        status, _, _ = third.request("GET", "/healthz")
        self.assertEqual(status, 503)


if __name__ == "__main__":
    unittest.main(verbosity=2)
