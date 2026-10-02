"""End-to-end HTTP tests against the real server (in-process, ephemeral port)."""

import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import _bootstrap  # noqa: F401
from server import make_server


def base_payload(audit_id="http-case", stale=False, skew=False, serial=True):
    if stale:
        return {
            "audit_id": audit_id,
            "initial": {"x": 0},
            "transactions": [
                {"id": "T1", "start": 1, "commit": 5, "steps": [
                    {"op": "write", "key": "x", "value": 10}]},
                {"id": "T2", "start": 6, "commit": 8, "steps": [
                    {"op": "read", "key": "x", "observed": "initial"}]},
            ],
        }
    if skew:
        return {
            "audit_id": audit_id,
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
    return {
        "audit_id": audit_id,
        "initial": {"x": 1},
        "transactions": [
            {"id": "T1", "start": 1, "commit": 3, "steps": [
                {"op": "write", "key": "x", "value": 2}]},
            {"id": "T2", "start": 4, "commit": 6, "steps": [
                {"op": "read", "key": "x", "observed": {"source": "txn", "writer": "T1"}}]},
        ],
    }


class HttpServerTestBase(unittest.TestCase):
    def setUp(self):
        self.server: ThreadingHTTPServer = make_server("127.0.0.1", 0)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()

    def request(self, method, path, body=None, expect_error=False):
        url = f"http://127.0.0.1:{self.port}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, dict(resp.headers), json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            if not expect_error:
                raise
            return exc.code, dict(exc.headers), json.loads(exc.read().decode())


class HttpApiTests(HttpServerTestBase):
    def test_healthz(self):
        status, _, body = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"status": "ok"})

    def test_console_page_served(self):
        url = f"http://127.0.0.1:{self.port}/"
        with urllib.request.urlopen(url, timeout=5) as resp:
            status = resp.status
            content_type = resp.headers.get("Content-Type")
            html = resp.read().decode()
        self.assertEqual(status, 200)
        self.assertIn("text/html", content_type)
        self.assertIn("多版本", html)

    def test_submit_serializable_freezes_and_replays(self):
        payload = base_payload()
        status, headers, body = self.request("POST", "/api/audits", payload)
        self.assertEqual(status, 201)
        self.assertEqual(headers.get("X-Audit-Replayed"), "false")
        self.assertEqual(body["status"], "SERIALIZABLE")
        self.assertEqual(body["serial_order"], ["T1", "T2"])

        # identical payload replays the stored verdict verbatim
        status2, headers2, body2 = self.request("POST", "/api/audits", payload)
        self.assertEqual(status2, 200)
        self.assertEqual(headers2.get("X-Audit-Replayed"), "true")
        self.assertEqual(body2, body)

        # fetch by id returns the frozen verdict
        status3, _, body3 = self.request("GET", f"/api/audits/{payload['audit_id']}")
        self.assertEqual(status3, 200)
        self.assertEqual(body3, body)

    def test_changed_payload_under_same_id_is_rejected_and_not_overwritten(self):
        payload = base_payload(audit_id="frozen-id")
        status, _, original = self.request("POST", "/api/audits", payload)
        self.assertEqual(status, 201)

        changed = base_payload(audit_id="frozen-id", skew=True)
        status2, _, err = self.request("POST", "/api/audits", changed, expect_error=True)
        self.assertEqual(status2, 409)
        self.assertEqual(err["error"], "AUDIT_ID_CONFLICT")

        # the frozen record is untouched: GET still returns the SERIALIZABLE one
        status3, _, fetched = self.request("GET", "/api/audits/frozen-id")
        self.assertEqual(status3, 200)
        self.assertEqual(fetched["status"], "SERIALIZABLE")
        self.assertEqual(fetched, original)

        # and the original payload still replays
        status4, headers4, replay = self.request("POST", "/api/audits", payload)
        self.assertEqual(status4, 200)
        self.assertEqual(headers4.get("X-Audit-Replayed"), "true")
        self.assertEqual(replay, original)

    def test_stale_version_read_is_422_and_not_frozen(self):
        payload = base_payload(stale=True)
        status, _, body = self.request("POST", "/api/audits", payload, expect_error=True)
        self.assertEqual(status, 422)
        self.assertEqual(body["error"], "STALE_VERSION_READ")
        self.assertEqual(body["verdict"]["status"], "INVALID_READ")
        bad = body["verdict"]["invalid_reads"][0]
        self.assertEqual((bad["transaction"], bad["expected_writer"]), ("T2", "T1"))

        # deterministic diagnosis on an identical retry ...
        status2, _, body2 = self.request("POST", "/api/audits", payload, expect_error=True)
        self.assertEqual(status2, 422)
        self.assertEqual(body2, body)
        # ... but nothing was frozen
        status3, _, listing = self.request("GET", "/api/audits")
        self.assertEqual(status3, 200)
        self.assertNotIn("http-case", listing["audit_ids"])
        status4, _, _ = self.request("GET", "/api/audits/http-case", expect_error=True)
        self.assertEqual(status4, 404)

    def test_write_skew_is_frozen_as_not_serializable_with_cycle_evidence(self):
        payload = base_payload(skew=True)
        status, _, body = self.request("POST", "/api/audits", payload)
        self.assertEqual(status, 201)
        self.assertEqual(body["status"], "NOT_SERIALIZABLE")
        cycle = body["cycle"]
        self.assertEqual(cycle["length"], 2)
        self.assertEqual(cycle["vertices"], ["T1", "T2"])
        self.assertEqual(len(cycle["edges"]), 2)
        for edge in cycle["edges"]:
            self.assertIn(edge["key"], ("x", "y"))
            self.assertIn("from_step", edge)
            self.assertIn("to_step", edge)
            self.assertTrue(edge["reason"])

    def test_malformed_json_is_400(self):
        url = f"http://127.0.0.1:{self.port}/api/audits"
        req = urllib.request.Request(url, data=b"{not json", method="POST")
        req.add_header("Content-Type", "application/json")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 400)

    def test_structural_payload_error_is_400(self):
        bad = {"audit_id": "", "initial": {}, "transactions": []}
        status, _, body = self.request("POST", "/api/audits", bad, expect_error=True)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "INVALID_PAYLOAD")

    def test_unknown_audit_returns_404(self):
        status, _, body = self.request("GET", "/api/audits/no-such", expect_error=True)
        self.assertEqual(status, 404)
        self.assertEqual(body["error"], "AUDIT_NOT_FOUND")


if __name__ == "__main__":
    unittest.main(verbosity=2)
