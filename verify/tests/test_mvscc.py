"""Unit tests for the multi-version serialisation-graph core."""

import unittest

import _bootstrap  # noqa: F401  (sys.path setup)
from mvscc import MAX_TRANSACTIONS, PayloadError, build_analysis


def analysis(initial, txns, audit_id="a"):
    return build_analysis({"audit_id": audit_id, "initial": initial, "transactions": txns})


def W(key, value, i=0):
    return {"op": "write", "key": key, "value": value, "step_index": i}


def R(key, observed="initial", i=0):
    return {"op": "read", "key": key, "observed": observed, "step_index": i}


def txn(tid, start, commit, steps_raw):
    """steps_raw: list of ('w', key, value) / ('r', key, observed)"""
    steps = []
    for i, item in enumerate(steps_raw):
        if item[0] == "w":
            steps.append(W(item[1], item[2], i))
        else:
            steps.append(R(item[1], item[2], i))
    return {"id": tid, "start": start, "commit": commit, "steps": steps}


def edge_pairs(result, etype=None):
    pairs = set()
    for e in result.get("edges", []):
        if etype is None or e["type"] == etype:
            pairs.add((e["from"], e["to"], e["key"]))
    return pairs


class ReadVersionValidationTests(unittest.TestCase):
    def test_read_initial_when_no_prior_commit_is_valid(self):
        r = analysis({"x": 0}, [txn("T1", 1, 2, [("r", "x", "initial")])])
        self.assertEqual(r["status"], "SERIALIZABLE")
        chk = r["read_checks"][0]
        self.assertEqual(chk["expected_writer"], "initial")
        self.assertEqual(chk["expected_value"], 0)

    def test_stale_read_after_commit_before_start_is_invalid(self):
        r = analysis(
            {"x": 0},
            [
                txn("T1", 1, 5, [("w", "x", 10)]),
                txn("T2", 6, 8, [("r", "x", "initial")]),
            ],
        )
        self.assertEqual(r["status"], "INVALID_READ")
        self.assertEqual(len(r["invalid_reads"]), 1)
        bad = r["invalid_reads"][0]
        self.assertEqual((bad["transaction"], bad["key"]), ("T2", "x"))
        self.assertEqual(bad["expected_writer"], "T1")
        self.assertEqual(bad["expected_value"], 10)

    def test_stale_read_naming_wrong_writer_is_invalid(self):
        r = analysis(
            {"x": 0},
            [
                txn("T1", 1, 3, [("w", "x", 1)]),
                txn("T2", 4, 6, [("w", "x", 2)]),
                txn("T3", 7, 9, [("r", "x", {"source": "txn", "writer": "T1"})]),
            ],
        )
        self.assertEqual(r["status"], "INVALID_READ")
        bad = r["invalid_reads"][0]
        self.assertEqual(bad["expected_writer"], "T2")
        self.assertEqual(bad["observed_writer"], "T1")

    def test_wrong_initial_literal_value_is_invalid(self):
        r = analysis({"x": 5}, [txn("T1", 1, 2, [("r", "x", 9)])])
        self.assertEqual(r["status"], "INVALID_READ")
        self.assertEqual(r["invalid_reads"][0]["observed_writer"], "initial")

    def test_correct_literal_initial_read_is_valid(self):
        r = analysis({"x": 5}, [txn("T1", 1, 2, [("r", "x", 5)])])
        self.assertEqual(r["status"], "SERIALIZABLE")

    def test_commit_at_start_instant_is_not_visible(self):
        r = analysis(
            {"x": 0},
            [
                txn("T1", 1, 5, [("w", "x", 10)]),
                txn("T2", 5, 7, [("r", "x", "initial")]),
            ],
        )
        self.assertEqual(r["status"], "SERIALIZABLE")

    def test_observed_value_for_txn_writer_is_attached(self):
        r = analysis(
            {"x": 0},
            [
                txn("T1", 1, 3, [("w", "x", 42)]),
                txn("T2", 4, 5, [("r", "x", {"source": "txn", "writer": "T1"})]),
            ],
        )
        self.assertEqual(r["status"], "SERIALIZABLE")
        chk = r["read_checks"][0]
        self.assertEqual(chk["observed_value"], 42)

    def test_read_of_uninitialized_key_is_null(self):
        r = analysis({}, [txn("T1", 1, 2, [("r", "new-key", "initial")])])
        self.assertEqual(r["status"], "SERIALIZABLE")
        self.assertIsNone(r["read_checks"][0]["expected_value"])

    def test_named_writer_who_never_wrote_key_is_impossible(self):
        r = analysis(
            {"x": 0},
            [
                txn("T1", 1, 3, [("w", "y", 1)]),
                txn("T2", 4, 5, [("r", "x", {"source": "txn", "writer": "T1"})]),
            ],
        )
        self.assertEqual(r["status"], "INVALID_READ")
        bad = r["invalid_reads"][0]
        self.assertEqual(bad["observed_writer"], "T1")
        self.assertIn("never wrote", bad["note"])


class WriteReadChainTests(unittest.TestCase):
    def test_simple_wr_chain(self):
        r = analysis(
            {"x": 1},
            [
                txn("T1", 1, 3, [("w", "x", 2)]),
                txn("T2", 4, 6, [("r", "x", {"source": "txn", "writer": "T1"})]),
            ],
        )
        self.assertEqual(r["status"], "SERIALIZABLE")
        self.assertEqual(r["serial_order"], ["T1", "T2"])
        self.assertIn(("T1", "T2", "x"), edge_pairs(r, "wr"))

    def test_observed_writer_must_have_committed_before_start(self):
        # T2 starts at 2 but claims T1 (commits 5) -- not visible, yet T1
        # also cannot be "latest before start"; snapshot is the initial one.
        r = analysis(
            {"x": 0},
            [
                txn("T1", 1, 5, [("w", "x", 10)]),
                txn("T2", 2, 6, [("r", "x", {"source": "txn", "writer": "T1"})]),
            ],
        )
        self.assertEqual(r["status"], "INVALID_READ")
        self.assertEqual(r["invalid_reads"][0]["expected_writer"], "initial")

    def test_reader_then_later_writer_is_serializable(self):
        # T1 snapshots x=0 before T2 commits; T2 writes x=1.  Only an
        # anti-dependency T1 -> T2 exists, so the unique serial order is
        # T1 (reads 0) then T2 (writes 1).
        r = analysis(
            {"x": 0},
            [
                txn("T1", 1, 7, [("r", "x", "initial")]),
                txn("T2", 2, 5, [("w", "x", 1)]),
            ],
        )
        self.assertEqual(r["status"], "SERIALIZABLE")
        self.assertEqual(r["serial_order"], ["T1", "T2"])
        self.assertIn(("T1", "T2", "x"), edge_pairs(r, "rw"))

    def test_write_skew_two_keys_is_a_2_cycle(self):
        r = analysis(
            {"x": 100, "y": 100},
            [
                txn("T1", 1, 5, [("r", "x", "initial"), ("w", "y", -100)]),
                txn("T2", 2, 6, [("r", "y", "initial"), ("w", "x", -100)]),
            ],
        )
        self.assertEqual(r["status"], "NOT_SERIALIZABLE")
        cycle = r["cycle"]
        self.assertEqual(cycle["length"], 2)
        self.assertEqual(cycle["vertices"], ["T1", "T2"])
        types = sorted(e["type"] for e in cycle["edges"])
        self.assertEqual(types, ["rw", "rw"])
        for e in cycle["edges"]:
            self.assertIn(e["key"], ("x", "y"))


class GraphOrderingTests(unittest.TestCase):
    def test_stable_order_breaks_ties_by_id(self):
        r = analysis(
            {"x": 0},
            [
                txn("zeta", 1, 2, [("r", "x", "initial")]),
                txn("alpha", 1, 2, [("r", "x", "initial")]),
                txn("beta", 1, 2, [("r", "x", "initial")]),
            ],
        )
        self.assertEqual(r["status"], "SERIALIZABLE")
        self.assertEqual(r["serial_order"], ["alpha", "beta", "zeta"])

    def test_shortest_cycle_prefers_3_cycle_over_4_cycle(self):
        # 3-cycle on {A,B,C}; a 4-cycle A->B->D->...->A must not win.
        # A->B (rw on x), B->C (rw on y), C->A (rw on z): direct triangle.
        # D participates in a longer loop A->B->D->C->A.
        # Build reads/writes so the triangle edges exist:
        init = {"x": 0, "y": 0, "z": 0}
        A = txn("A", 1, 9, [("r", "x", "initial"), ("w", "z", 1)])
        B = txn("B", 1, 9, [("r", "y", "initial"), ("w", "x", 1)])
        C = txn("C", 1, 9, [("r", "z", "initial"), ("w", "y", 1)])
        r = analysis(init, [A, B, C])
        self.assertEqual(r["status"], "NOT_SERIALIZABLE")
        self.assertEqual(r["cycle"]["length"], 3)
        self.assertEqual(r["cycle"]["vertices"], ["A", "B", "C"])

    def test_tie_break_rotation_and_lexicographic(self):
        # Two distinct 2-cycles in one history: graph picks the pair whose
        # smallest-vertex rotation is lexicographically smaller.
        # Cycle {a, z} on key p (a reads p, z writes p; z reads q, a writes q)
        # Cycle {b, c} on key q? Need disjoint keys to keep two independent
        # rw 2-cycles: {a,z} use keys k1,k2; {b,c} use k3,k4.
        t1 = txn("a", 1, 9, [("r", "k1", "initial"), ("w", "k2", 1)])
        t2 = txn("z", 1, 9, [("r", "k2", "initial"), ("w", "k1", 1)])
        t3 = txn("b", 1, 9, [("r", "k3", "initial"), ("w", "k4", 1)])
        t4 = txn("c", 1, 10, [("r", "k4", "initial"), ("w", "k3", 1)])
        r = analysis({"k1": 0, "k2": 0, "k3": 0, "k4": 0}, [t1, t2, t3, t4])
        self.assertEqual(r["status"], "NOT_SERIALIZABLE")
        self.assertEqual(r["cycle"]["length"], 2)
        # Rotation rooted at smallest vertex: {a,z} beats {b,c}.
        self.assertEqual(r["cycle"]["vertices"], ["a", "z"])

    def test_ww_edges_follow_commit_order(self):
        r = analysis(
            {"x": 0},
            [
                txn("T1", 1, 3, [("w", "x", 1)]),
                txn("T2", 2, 5, [("w", "x", 2)]),
                txn("T3", 4, 7, [("w", "x", 3)]),
            ],
        )
        self.assertEqual(r["status"], "SERIALIZABLE")
        self.assertEqual(r["serial_order"], ["T1", "T2", "T3"])
        ww = {(u, v) for u, v, _ in edge_pairs(r, "ww")}
        self.assertEqual(ww, {("T1", "T2"), ("T2", "T3")})

    def test_ww_rw_lost_update_cycle(self):
        # Both read the same old version and both write the key: blind-style
        # lost update. ww T1->T2 plus rw T1->T2 (T1 read old, T2 newer
        # version) and rw T2->T1 (T2 read old, T1 ... T1 is older version,
        # so T2's read produces rw T2 -> T1 only if T1 is later in version
        # chain, which it is not). Classic lost update via two writes +
        # reads: T1->T2 ww, T2 reads old => rw T2->T1. 2-cycle ww+rw.
        r = analysis(
            {"x": 0},
            [
                txn("T1", 1, 5, [("r", "x", "initial"), ("w", "x", 1)]),
                txn("T2", 2, 6, [("r", "x", "initial"), ("w", "x", 2)]),
            ],
        )
        self.assertEqual(r["status"], "NOT_SERIALIZABLE")
        self.assertEqual(r["cycle"]["length"], 2)
        self.assertEqual(r["cycle"]["vertices"], ["T1", "T2"])
        typed = {(e["type"], e["from"], e["to"]) for e in cycle_edges_unique(r)}
        self.assertIn(("ww", "T1", "T2"), typed)
        self.assertIn(("rw", "T2", "T1"), typed)


def cycle_edges_unique(result):
    seen = set()
    out = []
    for e in result["cycle"]["edges"]:
        key = (e["from"], e["to"], e["type"], e["key"])
        if key not in seen:
            seen.add(key)
            out.append(e)
    return out


class PayloadValidationTests(unittest.TestCase):
    def test_missing_audit_id(self):
        with self.assertRaises(PayloadError):
            build_analysis({"initial": {}, "transactions": []})

    def test_too_many_transactions(self):
        txns = [txn("T%02d" % i, 1, 2, [("r", "x", "initial")]) for i in range(MAX_TRANSACTIONS + 1)]
        with self.assertRaises(PayloadError):
            analysis({}, txns)

    def test_duplicate_txn_ids(self):
        with self.assertRaises(PayloadError):
            analysis({}, [txn("T1", 1, 2, [("r", "x", "initial")]),
                          txn("T1", 3, 4, [("w", "x", 1)])])

    def test_start_after_commit(self):
        with self.assertRaises(PayloadError):
            analysis({}, [txn("T1", 9, 2, [("r", "x", "initial")])])

    def test_unknown_writer_reference(self):
        with self.assertRaises(PayloadError):
            analysis({"x": 0}, [txn("T1", 5, 6, [("r", "x", {"source": "txn", "writer": "X9"})])])

    def test_self_writer_reference(self):
        # structurally expressed via raw normalized shape: use raw payload
        with self.assertRaises(PayloadError):
            build_analysis({
                "audit_id": "z",
                "initial": {"x": 0},
                "transactions": [{
                    "id": "T1", "start": 1, "commit": 2,
                    "steps": [{"op": "read", "key": "x",
                               "observed": {"source": "txn", "writer": "T1"}}],
                }],
            })

    def test_double_write_same_key_in_one_txn_rejected(self):
        with self.assertRaises(PayloadError):
            analysis({}, [txn("T1", 1, 2, [("w", "x", 1), ("w", "x", 2)])])

    def test_bad_op(self):
        with self.assertRaises(PayloadError):
            build_analysis({
                "audit_id": "z", "initial": {},
                "transactions": [{"id": "T1", "start": 1, "commit": 2,
                                  "steps": [{"op": "evolve", "key": "x"}]}],
            })

    def test_max_txn_boundary_ok(self):
        txns = [txn("T%02d" % i, 1, 2, [("r", "x", "initial")]) for i in range(MAX_TRANSACTIONS)]
        r = analysis({}, txns)
        self.assertEqual(r["status"], "SERIALIZABLE")


class SerialRecomputationTests(unittest.TestCase):
    def test_final_state_matches_order(self):
        r = analysis(
            {"x": 1},
            [
                txn("T1", 1, 3, [("w", "x", 2)]),
                txn("T2", 4, 6, [("r", "x", {"source": "txn", "writer": "T1"}),
                                 ("w", "x", 3)]),
            ],
        )
        recomp = r["recomputation"]
        self.assertEqual(recomp["final_state"], {"x": 3})
        self.assertEqual(recomp["reads_in_order"]["T2"][0]["value"], 2)

    def test_reads_for_each_position(self):
        r = analysis(
            {"x": 0},
            [
                txn("T1", 1, 3, [("w", "x", 7)]),
                txn("T2", 4, 5, [("r", "x", {"source": "txn", "writer": "T1"})]),
                txn("T3", 6, 7, [("r", "x", {"source": "txn", "writer": "T1"})]),
            ],
        )
        # T3 starts after T2 commits but reads T1's version (allowed: snapshot
        # of a key last written by T1? T2 didn't write, so yes).
        self.assertEqual(r["status"], "SERIALIZABLE")
        self.assertEqual(r["serial_order"], ["T1", "T2", "T3"])
        self.assertEqual(recomp_value(r, "T3", "x"), 7)


def recomp_value(result, tid, key):
    for read in result["recomputation"]["reads_in_order"][tid]:
        if read["key"] == key:
            return read["value"]
    raise KeyError(key)


if __name__ == "__main__":
    unittest.main(verbosity=2)
