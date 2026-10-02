"""Tests for the durable frozen audit-record store."""

import os
import tempfile
import threading
import unittest

import _bootstrap  # noqa: F401
from store import (
    FRAME_MAGIC,
    ConflictError,
    FrozenStore,
    _pack_frame,
    canonical_fingerprint,
)


class FingerprintTests(unittest.TestCase):
    def test_key_order_does_not_change_fingerprint(self):
        a = {"audit_id": "x", "initial": {"a": 1, "b": 2}, "transactions": []}
        b = {"transactions": [], "initial": {"b": 2, "a": 1}, "audit_id": "x"}
        self.assertEqual(canonical_fingerprint(a), canonical_fingerprint(b))

    def test_value_change_changes_fingerprint(self):
        a = {"audit_id": "x", "initial": {"a": 1}}
        b = {"audit_id": "x", "initial": {"a": 2}}
        self.assertNotEqual(canonical_fingerprint(a), canonical_fingerprint(b))


class FrozenStoreTests(unittest.TestCase):
    def setUp(self):
        self.store = FrozenStore()

    def tearDown(self):
        self.store.close()

    def test_first_submit_freezes_second_identical_replays(self):
        payload = {"audit_id": "a1"}
        verdict = {"status": "SERIALIZABLE"}
        v1, replayed1 = self.store.submit(payload, verdict)
        self.assertFalse(replayed1)
        v2, replayed2 = self.store.submit(dict(payload), verdict)
        self.assertTrue(replayed2)
        self.assertEqual(v1, v2)

    def test_different_payload_same_id_conflicts_and_preserves_record(self):
        self.store.submit({"audit_id": "a1", "v": 1}, {"status": "SERIALIZABLE"})
        with self.assertRaises(ConflictError):
            self.store.submit({"audit_id": "a1", "v": 2}, {"status": "NOT_SERIALIZABLE"})
        record = self.store.get("a1")
        self.assertEqual(record["verdict"], {"status": "SERIALIZABLE"})
        # the rejected payload never replaced the fingerprint
        verdict, replayed = self.store.submit({"audit_id": "a1", "v": 1}, {})
        self.assertTrue(replayed)
        self.assertEqual(verdict["status"], "SERIALIZABLE")

    def test_get_missing_returns_none(self):
        self.assertIsNone(self.store.get("ghost"))

    def test_distinct_ids_are_independent(self):
        self.store.submit({"audit_id": "a"}, {"status": "SERIALIZABLE"})
        _, replayed = self.store.submit({"audit_id": "b"}, {"status": "SERIALIZABLE"})
        self.assertFalse(replayed)


class JournalPaths(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "nested", "frozen.journal")

    def tearDown(self):
        for value in list(vars(self).values()):
            if isinstance(value, FrozenStore):
                value.close()
        for store in getattr(self, "_stores", []):
            store.close()
        self.tmp.cleanup()

    def mk(self, path=None):
        store = FrozenStore(self.path if path is None else path)
        self._stores = getattr(self, "_stores", [])
        self._stores.append(store)
        return store

    def frame_count(self):
        with open(self.path, "rb") as fh:
            return fh.read().count(FRAME_MAGIC)


class DurableJournalTests(JournalPaths):
    def payload(self, audit_id="a1", value=1):
        return {"audit_id": audit_id, "initial": {"x": value}, "transactions": []}

    def test_freeze_is_durable_and_replays_after_reopen(self):
        store = self.mk()
        verdict = {"status": "SERIALIZABLE", "serial_order": ["T1", "T2"]}
        got, replayed = store.submit(self.payload("a1", 1), verdict)
        self.assertFalse(replayed)
        self.assertEqual(got, verdict)
        self.assertTrue(os.path.exists(self.path))
        self.assertEqual(self.frame_count(), 1)
        store.close()

        # A brand-new store process reopens the journal and reconstructs
        # the audit index exactly.
        reopened = self.mk()
        healthy, _ = reopened.health()
        self.assertTrue(healthy)
        self.assertEqual(reopened.stats()["replayed"], 1)
        self.assertEqual(reopened.ids(), ["a1"])
        record = reopened.get("a1")
        self.assertEqual(record["verdict"], verdict)
        self.assertEqual(record["fingerprint"], canonical_fingerprint(self.payload("a1", 1)))

    def test_same_payload_replays_before_and_after_restart(self):
        store = self.mk()
        store.submit(self.payload("a1", 1), {"status": "SERIALIZABLE", "n": 1})
        store.close()

        reopened = self.mk()
        verdict, replayed = reopened.submit(self.payload("a1", 1), {"status": "DIFFERENT"})
        self.assertTrue(replayed)
        self.assertEqual(verdict, {"status": "SERIALIZABLE", "n": 1})
        # replay never appends a second frame
        self.assertEqual(self.frame_count(), 1)

    def test_changed_payload_conflicts_after_restart_and_never_overwrites(self):
        store = self.mk()
        store.submit(self.payload("a1", 1), {"status": "SERIALIZABLE"})
        store.close()

        reopened = self.mk()
        with self.assertRaises(ConflictError):
            reopened.submit(self.payload("a1", 2), {"status": "NOT_SERIALIZABLE"})
        # the recovered original verdict is intact
        self.assertEqual(reopened.get("a1")["verdict"], {"status": "SERIALIZABLE"})
        verdict, replayed = reopened.submit(self.payload("a1", 1), {})
        self.assertTrue(replayed)
        self.assertEqual(verdict["status"], "SERIALIZABLE")
        self.assertEqual(self.frame_count(), 1)

    def test_multiple_records_all_replay_in_order(self):
        store = self.mk()
        for i in range(5):
            store.submit(self.payload(f"id-{i}", i), {"status": "SERIALIZABLE", "i": i})
        store.close()

        reopened = self.mk()
        self.assertEqual(reopened.ids(), [f"id-{i}" for i in range(5)])
        for i in range(5):
            self.assertEqual(reopened.get(f"id-{i}")["verdict"]["i"], i)

    # ------------------------------------------------------------------
    # torn tail (interrupted / power-loss mid-write)
    # ------------------------------------------------------------------
    def test_torn_tail_without_commit_marker_is_discarded(self):
        store = self.mk()
        store.submit(self.payload("good"), {"status": "SERIALIZABLE"})
        store.close()

        # Simulate a process that died after the checksummed body but
        # before the END commit marker.
        dangling = {
            "audit_id": "torn",
            "fingerprint": canonical_fingerprint(self.payload("torn")),
            "payload": self.payload("torn"),
            "verdict": {"status": "SERIALIZABLE"},
        }
        data, _commit = _pack_frame(dangling)
        with open(self.path, "ab") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())

        reopened = self.mk()
        healthy, reason = reopened.health()
        self.assertTrue(healthy, reason)
        self.assertTrue(reopened.stats()["torn_tail_discarded"])
        self.assertIsNone(reopened.get("torn"))  # never a readable conclusion
        self.assertIsNotNone(reopened.get("good"))
        # the partial bytes were physically removed ...
        self.assertEqual(self.frame_count(), 1)
        # ... and new freezes append cleanly after the recovered prefix
        reopened.submit(self.payload("after"), {"status": "SERIALIZABLE"})
        self.assertEqual(self.frame_count(), 2)
        self.assertEqual(reopened.ids(), ["after", "good"])

    def test_partial_garbage_tail_is_discarded(self):
        store = self.mk()
        store.submit(self.payload("good"), {"status": "SERIALIZABLE"})
        store.close()
        with open(self.path, "ab") as fh:
            fh.write(b"F1\nLEN 9999\n{\"partial")
            fh.flush()
            os.fsync(fh.fileno())

        reopened = self.mk()
        healthy, _ = reopened.health()
        self.assertTrue(healthy)
        self.assertEqual(reopened.ids(), ["good"])

    # ------------------------------------------------------------------
    # corrupted *committed* records
    # ------------------------------------------------------------------
    def test_corrupt_committed_frame_fails_health_even_at_tail(self):
        store = self.mk()
        store.submit(self.payload("good"), {"status": "SERIALIZABLE"})
        store.close()

        victim = {
            "audit_id": "damaged",
            "fingerprint": canonical_fingerprint(self.payload("damaged")),
            "payload": self.payload("damaged"),
            "verdict": {"status": "SERIALIZABLE"},
        }
        data, commit = _pack_frame(victim)
        # flip one payload byte but keep the commit marker: this is a
        # complete, previously confirmed record whose checksum now fails
        tampered = data[:data.find(b"{") + 2] + b"Z" + data[data.find(b"{") + 3:]
        self.assertEqual(len(tampered), len(data))
        with open(self.path, "ab") as fh:
            fh.write(tampered + commit)
            fh.flush()
            os.fsync(fh.fileno())

        reopened = self.mk()
        healthy, reason = reopened.health()
        self.assertFalse(healthy)
        self.assertIn("checksum", reason)
        # the undamaged prefix is still recovered ...
        self.assertEqual(reopened.get("good")["verdict"], {"status": "SERIALIZABLE"})
        # ... while the corrupted record yields no conclusion
        self.assertIsNone(reopened.get("damaged"))

    def test_garbage_followed_by_valid_frame_is_corruption_not_torn_tail(self):
        store = self.mk()
        store.submit(self.payload("good"), {"status": "SERIALIZABLE"})
        store.close()

        later = {
            "audit_id": "later",
            "fingerprint": canonical_fingerprint(self.payload("later")),
            "payload": self.payload("later"),
            "verdict": {"status": "SERIALIZABLE"},
        }
        data, commit = _pack_frame(later)
        with open(self.path, "ab") as fh:
            fh.write(b"F1\nGARBAGE WITHOUT COMMIT MARKER\n")
            fh.write(data + commit)
            fh.flush()
            os.fsync(fh.fileno())

        reopened = self.mk()
        healthy, _ = reopened.health()
        self.assertFalse(healthy)
        self.assertEqual(reopened.get("good")["verdict"], {"status": "SERIALIZABLE"})

    def test_fingerprint_mismatch_in_committed_frame_fails_health(self):
        store = self.mk()
        store.submit(self.payload("good"), {"status": "SERIALIZABLE"})
        store.close()

        bogus = {
            "audit_id": "bogus",
            "fingerprint": "0" * 64,
            "payload": self.payload("bogus"),
            "verdict": {"status": "SERIALIZABLE"},
        }
        data, commit = _pack_frame(bogus)  # checksum covers the lying record
        with open(self.path, "ab") as fh:
            fh.write(data + commit)
            fh.flush()
            os.fsync(fh.fileno())

        reopened = self.mk()
        healthy, reason = reopened.health()
        self.assertFalse(healthy)
        self.assertIn("fingerprint", reason)

    # ------------------------------------------------------------------
    # concurrency
    # ------------------------------------------------------------------
    def test_concurrent_identical_submits_freeze_exactly_once(self):
        store = self.mk()
        payload = self.payload("race")
        verdict = {"status": "SERIALIZABLE"}
        results = []
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            try:
                _v, replayed = store.submit(payload, verdict)
                results.append(replayed)
            except ConflictError:  # pragma: no cover - must not happen
                results.append("conflict")

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(results), 8)
        self.assertEqual(results.count(False), 1, results)
        self.assertEqual(results.count(True), 7, results)
        self.assertEqual(self.frame_count(), 1)
        store.close()

        reopened = self.mk()
        self.assertEqual(reopened.ids(), ["race"])
        _v, replayed = reopened.submit(payload, verdict)
        self.assertTrue(replayed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
