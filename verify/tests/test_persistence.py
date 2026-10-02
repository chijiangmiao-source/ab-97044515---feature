"""Durability / recovery tests for the frozen-record log.

Covers the ground-review requirements:

* a first freeze is verifiably on disk before success is observable;
* restart replays identical verdicts and keeps the conflict guarantee;
* an unfinished trailing write never becomes a readable conclusion;
* a corrupted *committed* record fails health explicitly;
* concurrent identical submissions collapse onto one frozen record.
"""

import json
import os
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import _bootstrap  # noqa: F401
from store import ConflictError, FrozenStore, RecordIntegrityError

VERDICT = {
    "status": "SERIALIZABLE",
    "serial_order": ["T1", "T2"],
    "recomputation": {"final_state": {"x": 3}, "reads_in_order": {}},
}
SKEW = {"status": "NOT_SERIALIZABLE", "cycle": {"length": 2}}


class _TempLog:
    def __init__(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "audit.log")

    def raw(self) -> bytes:
        return Path(self.path).read_bytes()

    def write_raw(self, data: bytes):
        Path(self.path).write_bytes(data)

    def reopen(self) -> FrozenStore:
        return FrozenStore(self.path)


class DurableFreezeTests(unittest.TestCase):
    def setUp(self):
        self.t = _TempLog()

    def test_record_file_exists_with_full_verdict_before_success_returns(self):
        store = self.t.reopen()
        payload = {"audit_id": "a1", "initial": {"x": 1}}
        verdict, replayed = store.submit(payload, VERDICT)
        self.assertFalse(replayed)
        on_disk = self.t.raw().decode()
        line = json.loads(on_disk)
        self.assertEqual(line["audit_id"], "a1")
        self.assertEqual(line["verdict"], VERDICT)
        self.assertTrue(line["checksum"].startswith("sha256:"))
        self.assertEqual(line["fingerprint"], store.get("a1")["fingerprint"])
        self.assertEqual(verdict, VERDICT)

    def test_restart_replays_exact_verdict_and_index(self):
        store = self.t.reopen()
        store.submit({"audit_id": "a1", "v": 1}, VERDICT)
        store.submit({"audit_id": "a2", "v": 2}, SKEW)

        restarted = self.t.reopen()
        self.assertTrue(restarted.healthy)
        self.assertEqual(restarted.ids(), ["a1", "a2"])
        self.assertEqual(restarted.get("a1")["verdict"], VERDICT)
        verdict, replayed = restarted.submit({"audit_id": "a1", "v": 1}, VERDICT)
        self.assertTrue(replayed)
        self.assertEqual(verdict, VERDICT)

    def test_changed_payload_after_restart_still_conflicts(self):
        store = self.t.reopen()
        store.submit({"audit_id": "id", "v": 1}, VERDICT)
        restarted = self.t.reopen()
        with self.assertRaises(ConflictError):
            restarted.submit({"audit_id": "id", "v": 2}, SKEW)
        # the original survived both the conflict attempt and the restart
        self.assertEqual(restarted.get("id")["verdict"], VERDICT)

    def test_repeated_restarts_are_stable(self):
        store = self.t.reopen()
        store.submit({"audit_id": "a1"}, VERDICT)
        bytes_after_first = self.t.raw()
        for _ in range(3):
            again = self.t.reopen()
            self.assertTrue(again.healthy)
            again.submit({"audit_id": "a1"}, VERDICT)  # replay, no rewrite
        self.assertEqual(self.t.raw(), bytes_after_first)

    def test_concurrent_identical_submits_create_one_record(self):
        store = self.t.reopen()
        payload = {"audit_id": "race", "v": 7}
        outcomes = []

        def go():
            v, replayed = store.submit(payload, VERDICT)
            outcomes.append(replayed)
            return v

        with ThreadPoolExecutor(max_workers=8) as pool:
            verdicts = list(pool.map(lambda _: go(), range(8)))
        self.assertEqual(outcomes.count(False), 1, outcomes)
        self.assertEqual(sum(outcomes), 7)
        self.assertTrue(all(v == VERDICT for v in verdicts))
        lines = [l for l in self.t.raw().decode().splitlines() if l.strip()]
        race_lines = [json.loads(l) for l in lines if json.loads(l)["audit_id"] == "race"]
        self.assertEqual(len(race_lines), 1)
        # and the single record survives a restart
        self.assertEqual(self.t.reopen().ids(), ["race"])


class RecoveryTailTests(unittest.TestCase):
    def setUp(self):
        self.t = _TempLog()
        store = self.t.reopen()
        store.submit({"audit_id": "good-1"}, VERDICT)
        store.submit({"audit_id": "good-2"}, SKEW)

    def test_unterminated_tail_is_dropped_and_never_readable(self):
        # Simulate a crash mid write: a full-looking record without the
        # trailing commit newline appended to an otherwise intact log.
        self.t.write_raw(self.t.raw() + b'{"version":1,"audit_id":"half-written"')
        reopened = self.t.reopen()
        self.assertTrue(reopened.healthy)
        self.assertEqual(reopened.ids(), ["good-1", "good-2"])
        self.assertIsNone(reopened.get("half-written"))
        self.assertGreater(reopened.dropped_tail_bytes, 0)

    def test_tail_that_looks_complete_is_still_dropped_without_newline(self):
        store = FrozenStore(self.t.path)
        fabricated = {
            "version": 1,
            "audit_id": "forged",
            "fingerprint": "0" * 64,
            "verdict": VERDICT,
        }
        from store import _record_checksum  # noqa: PLC0415
        fabricated["checksum"] = _record_checksum(fabricated)
        blob = json.dumps(fabricated, separators=(",", ":")).encode()
        self.t.write_raw(self.t.raw() + blob)  # no terminating newline
        reopened = self.t.reopen()
        self.assertTrue(reopened.healthy)
        self.assertIsNone(reopened.get("forged"))

    def test_abandoned_temp_files_are_cleaned_on_recovery(self):
        tmp = Path(self.t.dir) / ".audit.log.999.1.dead.tmp"
        tmp.write_bytes(b"junk")
        reopened = self.t.reopen()
        self.assertTrue(reopened.healthy)
        self.assertFalse(tmp.exists())
        self.assertEqual(reopened.ids(), ["good-1", "good-2"])


class CorruptionTests(unittest.TestCase):
    def setUp(self):
        self.t = _TempLog()
        store = self.t.reopen()
        store.submit({"audit_id": "good-1"}, VERDICT)
        store.submit({"audit_id": "good-2"}, SKEW)

    def _tamper_committed_line(self):
        lines = self.t.raw().splitlines()
        first = json.loads(lines[0])
        # alter the payload fingerprint while keeping valid JSON and length
        fp = first["fingerprint"]
        lines[0] = lines[0].replace(
            b'"fingerprint":"' + fp.encode()[:2],
            b'"fingerprint":"' + (b"ff" if fp[:2] != "ff" else b"00"),
            1,
        )
        self.t.write_raw(b"\n".join(lines) + b"\n")

    def test_corrupt_committed_record_makes_store_unhealthy(self):
        self._tamper_committed_line()
        reopened = self.t.reopen()
        self.assertFalse(reopened.healthy)
        self.assertIn("checksum", reopened.health_error)
        # a log that did not fully check out yields no readable conclusions
        self.assertEqual(reopened.ids(), [])
        self.assertIsNone(reopened.get("good-1"))

    def test_unhealthy_store_refuses_new_freezes(self):
        self._tamper_committed_line()
        reopened = self.t.reopen()
        with self.assertRaises(RecordIntegrityError):
            reopened.submit({"audit_id": "new"}, VERDICT)

    def test_truncated_json_committed_line_is_corruption(self):
        lines = self.t.raw().splitlines()
        lines[0] = lines[0][: len(lines[0]) // 2]
        self.t.write_raw(b"\n".join(lines) + b"\n")
        reopened = self.t.reopen()
        self.assertFalse(reopened.healthy)
        self.assertIn("JSON", reopened.health_error)

    def test_missing_checksum_is_corruption(self):
        lines = self.t.raw().splitlines()
        first = json.loads(lines[0])
        del first["checksum"]
        lines[0] = json.dumps(first, separators=(",", ":")).encode()
        self.t.write_raw(b"\n".join(lines) + b"\n")
        reopened = self.t.reopen()
        self.assertFalse(reopened.healthy)

    def test_tampered_verdict_but_clean_tail_still_healthy_partial_drop(self):
        # Damage only inside an unterminated tail: must NOT fail health.
        self.t.write_raw(self.t.raw() + b'{"broken": true, "no": ')
        reopened = self.t.reopen()
        self.assertTrue(reopened.healthy)
        self.assertEqual(reopened.ids(), ["good-1", "good-2"])


class MemoryStoreTests(unittest.TestCase):
    def test_none_path_keeps_in_memory_behaviour(self):
        store = FrozenStore()
        self.assertTrue(store.healthy)
        v, replayed = store.submit({"audit_id": "m"}, VERDICT)
        self.assertFalse(replayed)
        self.assertEqual(v, VERDICT)


if __name__ == "__main__":
    unittest.main(verbosity=2)
