"""Adversarial cross-check: an independent, deliberately simple reimplementation
of the audit semantics, fuzzed against src/mvscc.py over random histories.

Independent choices made here on purpose:
* visibility by literally replaying commits on a timeline;
* graph cycle test by three-colour DFS;
* shortest / lexicographically-smallest cycle by enumerating every simple
  cycle from each minimum-vertex root;
* serial-order legality checked directly against every edge.
"""

import itertools
import os
import random
import sys
from collections import defaultdict

_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, _SRC)
from mvscc import build_analysis  # noqa: E402


def oracle(payload):
    initial = payload["initial"]
    txns = {t["id"]: t for t in payload["transactions"]}
    keys = set(initial)
    for t in payload["transactions"]:
        for s in t["steps"]:
            keys.add(s["key"])

    def written(tid, key):
        for s in txns[tid]["steps"]:
            if s["op"] == "write" and s["key"] == key:
                return s["value"]
        raise KeyError

    # --- read validity via plain timeline replay ----------------------
    invalid = []
    for t in payload["transactions"]:
        for si, s in enumerate(t["steps"]):
            if s["op"] != "read":
                continue
            prior = [(txns[w]["commit"], w)
                     for w in txns
                     for st in txns[w]["steps"]
                     if st["op"] == "write" and st["key"] == s["key"]
                     and txns[w]["commit"] < t["start"]]
            if prior:
                exp_writer = max(prior)[1]
                exp_val = written(exp_writer, s["key"])
            else:
                exp_writer, exp_val = "initial", initial.get(s["key"])
            obs = s["observed"]
            obs_writer = obs["writer"] if isinstance(obs, dict) else "initial"
            ok = obs_writer == exp_writer
            if ok and not isinstance(obs, dict) and obs != "initial":
                ok = obs == exp_val
            if not ok:
                invalid.append((t["id"], si, s["key"], exp_writer))
    return invalid, txns, keys


def oracle_graph(payload, txns, keys):
    """Second, independent formulation of the MVSG edges (as typed pairs)."""
    edges = set()
    # commit-ordered writer list per key
    writers = defaultdict(list)
    for tid, t in txns.items():
        for si, s in enumerate(t["steps"]):
            if s["op"] == "write":
                writers[s["key"]].append((t["commit"], tid))
    chains = {k: [w for _, w in sorted(v)] for k, v in writers.items()}

    # ww
    for k, chain in chains.items():
        for a, b in zip(chain, chain[1:]):
            edges.add((a, b, "ww", k))
    # wr + rw
    for tid, t in txns.items():
        for si, s in enumerate(t["steps"]):
            if s["op"] != "read":
                continue
            k = s["key"]
            obs = s["observed"]
            v0 = obs["writer"] if isinstance(obs, dict) else "initial"
            if isinstance(obs, dict):
                edges.add((v0, tid, "wr", k))
            for w in chains.get(k, []):
                if w == tid or w == v0:
                    continue
                if v0 == "initial":
                    # reader already validated: w commits >= reader start,
                    # hence w must follow the reader.
                    edges.add((tid, w, "rw", k))
                else:
                    if w in chains[k] and v0 in chains[k] \
                            and chains[k].index(w) > chains[k].index(v0):
                        edges.add((tid, w, "rw", k))
    adj = defaultdict(set)
    for a, b, _, _ in edges:
        adj[a].add(b)
    for tid in txns:
        adj.setdefault(tid, set())
    return edges, adj


def has_cycle_dfs(adj):
    colour = {n: 0 for n in adj}

    def visit(n):
        colour[n] = 1
        for m in adj[n]:
            if colour[m] == 1 or (colour[m] == 0 and visit(m)):
                return True
        colour[n] = 2
        return False

    return any(colour[n] == 0 and visit(n) for n in list(adj))


def best_simple_cycle(adj):
    nodes = sorted(adj)
    best = None
    for root in nodes:
        allowed = {n for n in nodes if n >= root}

        def dfs(node, path, onpath):
            nonlocal best
            for nxt in sorted(adj[node]):
                if nxt not in allowed:
                    continue
                if nxt == root and len(path) >= 1:
                    cyc = tuple(path)
                    cand = (len(cyc), cyc)
                    if best is None or cand < best:
                        best = cand
                elif nxt not in onpath:
                    dfs(nxt, path + [nxt], onpath | {nxt})

        dfs(root, [root], {root})
    return best


def random_history(rng):
    nkeys = rng.randint(1, 3)
    keys = [f"k{i}" for i in range(nkeys)]
    initial = {k: rng.randint(0, 5) for k in keys}
    ntxn = rng.randint(1, 5)
    ids = [f"T{i}" for i in range(ntxn)]
    meta = {tid: (rng.randint(0, 8), 0) for tid in ids}
    meta = {tid: (start, start + rng.randint(0, 4)) for tid, (start, _) in meta.items()}

    # pre-roll each transaction's writes: key -> value (at most one per key)
    writes = {}
    for tid in ids:
        wks = set(rng.sample(keys, rng.randint(0, min(len(keys), 2))))
        writes[tid] = {k: rng.randint(0, 9) for k in wks}

    def prior_writers(tid, key, start):
        out = [(meta[w][1], w) for w in ids
               if w != tid and key in writes[w] and meta[w][1] < start]
        return sorted(out)

    txns = []
    for tid in ids:
        start, commit = meta[tid]
        steps = []
        used = set()
        for _ in range(rng.randint(1, 4)):
            k = rng.choice(keys)
            if k in used:
                continue
            used.add(k)
            write_it = k in writes[tid] and rng.random() < 0.5
            if write_it:
                steps.append({"op": "write", "key": k, "value": writes[tid][k]})
            else:
                prior = prior_writers(tid, k, start)
                roll = rng.random()
                if prior and roll < 0.7:
                    obs = {"source": "txn", "writer": prior[-1][1]}      # correct
                elif prior and roll < 0.82:
                    obs = {"source": "txn", "writer": prior[0][1]}       # stale writer
                elif not prior and roll < 0.97:
                    obs = "initial" if rng.random() < 0.85 else initial[k]
                elif prior and roll < 0.92:
                    obs = "initial"                                       # stale (vs writer)
                else:
                    obs = rng.randint(100, 999)                           # wrong literal
                steps.append({"op": "read", "key": k, "observed": obs})
        if not steps:
            steps.append({"op": "read", "key": rng.choice(keys), "observed": "initial"})
        txns.append({"id": tid, "start": start, "commit": commit, "steps": steps})
    return {"audit_id": "fuzz", "initial": initial, "transactions": txns}


def write_skew_history(rng, size):
    """Classic interlocking pattern: each of `size` txns reads a key the
    next txn writes and writes a key the previous txn read -> size-cycle."""
    keys = [f"k{i}" for i in range(size)]
    txns = []
    for i in range(size):
        read_key = keys[i]
        write_key = keys[(i - 1) % size]
        steps = [{"op": "read", "key": read_key, "observed": "initial"}]
        if write_key != read_key:
            steps.append({"op": "write", "key": write_key, "value": rng.randint(0, 9)})
        txns.append({"id": f"S{i}", "start": 1, "commit": 2 + i, "steps": steps})
    return {"audit_id": "fuzz", "initial": {k: 0 for k in keys}, "transactions": txns}


def main():
    rng = random.Random(20260930)
    trials = 400
    cases = [random_history(rng) for _ in range(trials)]
    # inject write-skew cycles of several lengths, including a 3 vs 4 choice:
    # two disjoint components where the shortest cycle must win
    cases.append(write_skew_history(rng, 2))
    cases.append(write_skew_history(rng, 3))
    cases.append(write_skew_history(rng, 4))
    cases.append(write_skew_history(rng, 5))
    stats = {"invalid": 0, "serializable": 0, "cyclic": 0}
    for i, payload in enumerate(cases):
        result = build_analysis(payload)
        invalid, txns, keys = oracle(payload)
        if invalid:
            assert result["status"] == "INVALID_READ", (i, payload, result["status"])
            got = {(r["transaction"], r["step"], r["key"]) for r in result["invalid_reads"]}
            assert {(a, b, c) for a, b, c, _ in invalid} == got, (i, invalid, got)
            stats["invalid"] += 1
            continue

        edges, adj = oracle_graph(payload, txns, keys)
        cyclic = has_cycle_dfs(adj)
        # typed pairs returned by the implementation
        impl_pairs = {(e["from"], e["to"], e["type"], e["key"]) for e in result["edges"]}
        assert impl_pairs == edges, (i, payload, impl_pairs ^ edges)

        if cyclic:
            assert result["status"] == "NOT_SERIALIZABLE", (i, payload, result["status"])
            stats["cyclic"] += 1
            length, cyc = best_simple_cycle(adj)
            assert result["cycle"]["length"] == length, (i, length, result["cycle"])
            assert tuple(result["cycle"]["vertices"]) == cyc, (i, cyc, result["cycle"]["vertices"])
            # every reported edge must exist
            for e in result["cycle"]["edges"]:
                assert e["to"] in adj[e["from"]], (i, e)
            # the path actually closes
            verts = result["cycle"]["vertices"]
            for a, b in zip(verts, verts[1:] + verts[:1]):
                assert b in adj[a], (i, a, b)
        else:
            assert result["status"] == "SERIALIZABLE", (i, payload, result["status"])
            stats["serializable"] += 1
            order = result["serial_order"]
            pos = {t: n for n, t in enumerate(order)}
            assert set(order) == set(txns) and len(order) == len(txns)
            for a, b, typ, k in edges:
                assert pos[a] < pos[b], (i, (a, b, typ, k), order)
            # id-heap tie-break: order must be the lexicographically smallest
            # topological order
            indeg = {n: 0 for n in adj}
            for n in adj:
                for m in adj[n]:
                    indeg[m] += 1
            avail = sorted(n for n, d in indeg.items() if d == 0)
            canonical = []
            indeg = dict(indeg)
            while avail:
                n = avail.pop(0)
                canonical.append(n)
                for m in sorted(adj[n]):
                    indeg[m] -= 1
                    if indeg[m] == 0:
                        avail.append(m)
                avail.sort()
            assert order == canonical, (i, order, canonical)

    print(f"fuzz OK over {trials} histories: {stats}")


if __name__ == "__main__":
    main()
