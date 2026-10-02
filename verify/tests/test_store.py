"""Tests for the frozen audit-record store."""

import unittest

import _bootstrap  # noqa: F401
from store import ConflictError, FrozenStore, canonical_fingerprint


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
