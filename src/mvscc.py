"""Multi-version concurrency-control audit core.

The auditor receives a frozen audit history:

* an ``initial`` key/value snapshot,
* a set of at most 24 transactions, each with a start timestamp
  (``start``), a commit timestamp (``commit``) and an ordered list of
  read/write steps,
* every read step declares what it observed: either the literal
  ``initial`` value or the id of the transaction whose write it read.

Two questions are answered:

1. **Version validity** -- did every read observe the newest version of
   the key that was committed *before the reading transaction started*
   (snapshot / first-committer-wins semantics)?  A read that violates
   this is reported as an ``INVALID_READ`` input error.
2. **View serialisability** -- is the history equivalent to some serial
   execution?  We build the multi-version serialisation graph with the
   three classic anti-dependencies:

   * write -> read / read-dependency edges (``ww``),
   * write -> write version-order edges (``ww``),
   * read -> later-write anti-dependency edges (``rw``).

   An acyclic graph yields one canonical serial order (topological order
   broken by transaction id).  A cycle is reported as the shortest cycle,
   ties broken by the lexicographically smallest id sequence.
"""

from __future__ import annotations

import heapq
from collections import defaultdict
from typing import Any

MAX_TRANSACTIONS = 24

INITIAL_SENTINEL = "initial"


class PayloadError(ValueError):
    """Raised when the submitted payload is malformed."""


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _require(cond: bool, message: str) -> None:
    if not cond:
        raise PayloadError(message)


def _is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def validate_payload(payload: Any) -> dict:
    """Validate the raw JSON payload and return a normalised copy."""
    _require(isinstance(payload, dict), "payload must be a JSON object")
    audit_id = payload.get("audit_id")
    _require(
        isinstance(audit_id, str) and 1 <= len(audit_id) <= 128,
        "audit_id must be a non-empty string (max 128 chars)",
    )

    initial = payload.get("initial", {})
    _require(isinstance(initial, dict), "initial must be an object of key/value pairs")
    for key, value in initial.items():
        _require(isinstance(key, str), "initial keys must be strings")
        _require(_is_scalar(value), f"initial value for {key!r} must be a scalar")

    txns = payload.get("transactions")
    _require(isinstance(txns, list), "transactions must be a list")
    _require(
        0 < len(txns) <= MAX_TRANSACTIONS,
        f"transactions must contain 1..{MAX_TRANSACTIONS} entries",
    )

    norm_txns = []
    seen_ids: set[str] = set()
    for index, raw in enumerate(txns):
        _require(isinstance(raw, dict), f"transactions[{index}] must be an object")
        txid = raw.get("id")
        _require(
            isinstance(txid, str) and 1 <= len(txid) <= 64,
            f"transactions[{index}].id must be a non-empty string",
        )
        _require(txid not in seen_ids, f"duplicate transaction id {txid!r}")
        seen_ids.add(txid)

        start = raw.get("start")
        commit = raw.get("commit")
        _require(
            isinstance(start, (int, float)) and not isinstance(start, bool),
            f"transaction {txid!r}: start must be a number",
        )
        _require(
            isinstance(commit, (int, float)) and not isinstance(commit, bool),
            f"transaction {txid!r}: commit must be a number",
        )
        _require(
            start <= commit,
            f"transaction {txid!r}: start ({start}) must be <= commit ({commit})",
        )

        steps = raw.get("steps", [])
        _require(isinstance(steps, list), f"transaction {txid!r}: steps must be a list")
        _require(len(steps) > 0, f"transaction {txid!r}: at least one step is required")

        norm_steps = []
        written_keys: set[str] = set()
        for s_index, step in enumerate(steps):
            where = f"transaction {txid!r} step {s_index}"
            _require(isinstance(step, dict), f"{where} must be an object")
            op = step.get("op")
            key = step.get("key")
            _require(isinstance(key, str) and key, f"{where}: key must be a non-empty string")
            if op == "read":
                observed = step.get("observed", INITIAL_SENTINEL)
                if isinstance(observed, dict):
                    source = observed.get("source")
                    _require(
                        source == "txn" and isinstance(observed.get("writer"), str),
                        f"{where}: read observation object must be "
                        '{"source": "txn", "writer": "<id>"}',
                    )
                    norm_observed = {"source": "txn", "writer": observed["writer"]}
                else:
                    _require(
                        observed == INITIAL_SENTINEL or _is_scalar(observed),
                        f"{where}: observed must be 'initial', a scalar or a "
                        'writer object {"source": "txn", ...}',
                    )
                    norm_observed = (
                        INITIAL_SENTINEL if observed == INITIAL_SENTINEL else observed
                    )
                norm_steps.append(
                    {
                        "op": "read",
                        "key": key,
                        "observed": norm_observed,
                        "step_index": s_index,
                    }
                )
            elif op == "write":
                _require("value" in step, f"{where}: write step requires a value")
                _require(_is_scalar(step["value"]), f"{where}: written value must be a scalar")
                _require(
                    key not in written_keys,
                    f"{where}: key {key!r} is written more than once in one transaction",
                )
                written_keys.add(key)
                norm_steps.append(
                    {
                        "op": "write",
                        "key": key,
                        "value": step["value"],
                        "step_index": s_index,
                    }
                )
            else:
                raise PayloadError(f"{where}: op must be 'read' or 'write'")

        norm_txns.append({"id": txid, "start": start, "commit": commit, "steps": norm_steps})

    # writer references must resolve to known transactions
    for txn in norm_txns:
        for step in txn["steps"]:
            if step["op"] == "read" and isinstance(step["observed"], dict):
                writer = step["observed"]["writer"]
                _require(
                    writer in seen_ids,
                    f"transaction {txn['id']!r} step {step['step_index']}: "
                    f"observed writer {writer!r} is not a known transaction",
                )
                _require(
                    writer != txn["id"],
                    f"transaction {txn['id']!r} step {step['step_index']}: "
                    "a read cannot observe its own transaction",
                )

    return {"audit_id": audit_id, "initial": dict(initial), "transactions": norm_txns}


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

def _latest_versions(txns, initial_keys):
    """For every transaction return the committed-version landscape visible
    at its start timestamp:

    * latest_before[key]  -> writer id ('initial' or a txn) committed at the
      greatest commit time strictly before the transaction started;
    * value_before[key]   -> the value that writer installed.

    Commits at exactly the start instant are not visible.
    """
    committed = defaultdict(list)  # key -> [(commit_time, writer_id)]
    for txn in txns:
        for step in txn["steps"]:
            if step["op"] == "write":
                committed[step["key"]].append((txn["commit"], txn["id"]))
    for entries in committed.values():
        entries.sort()

    latest = {}
    values = {}
    initial_key_set = set(initial_keys)
    for txn in txns:
        lb = {}
        vb = {}
        start = txn["start"]
        for key in initial_key_set | set(committed):
            candidates = [e for e in committed[key] if e[0] < start]
            if candidates:
                writer = candidates[-1][1]
                lb[key] = writer
                vb[key] = _written_value(txns, writer, key)
            else:
                lb[key] = INITIAL_SENTINEL
                vb[key] = initial_value(initial_keys, key)
        latest[txn["id"]] = lb
        values[txn["id"]] = vb
    return latest, values


def initial_value(initial, key):
    return initial.get(key)


def _written_value(txns, writer_id, key):
    writer = next(t for t in txns if t["id"] == writer_id)
    for step in writer["steps"]:
        if step["op"] == "write" and step["key"] == key:
            return step["value"]
    raise RuntimeError(f"internal: {writer_id} did not write {key!r}")


_MISSING = object()


def _maybe_written_value(txns, writer_id, key):
    writer = next(t for t in txns if t["id"] == writer_id)
    for step in writer["steps"]:
        if step["op"] == "write" and step["key"] == key:
            return step["value"]
    return _MISSING


def _add_edge(graph, fro, to, edge):
    """Record a dependency edge.  Several edges between the same ordered
    pair (over different keys) are all retained as evidence; graph
    algorithms treat the pair as a single adjacency."""
    graph[fro].setdefault(to, []).append(edge)


def build_analysis(payload: dict) -> dict:
    """Run validation, version checks and graph construction.

    Returns a result dict.  ``status`` is one of:

    * ``INVALID_READ`` -- a read observed a stale/impossible version;
    * ``SERIALIZABLE`` -- graph acyclic, a serial order is given;
    * ``NOT_SERIALIZABLE`` -- graph cyclic, a shortest cycle is given.
    """
    norm = validate_payload(payload)
    initial = norm["initial"]
    txns = norm["transactions"]
    txn_by_id = {t["id"]: t for t in txns}
    all_keys = set(initial)
    for txn in txns:
        all_keys.update(s["key"] for s in txn["steps"])

    # Writers per key, in commit order (ties broken by transaction id so the
    # version chain itself is deterministic).
    writers_by_key = defaultdict(list)
    for txn in txns:
        for step in txn["steps"]:
            if step["op"] == "write":
                writers_by_key[step["key"]].append(
                    (txn["commit"], txn["id"], step["step_index"])
                )
    for key, entries in writers_by_key.items():
        entries.sort(key=lambda e: (e[0], e[1]))

    latest_before, value_before = _latest_versions(txns, initial)

    # ------------------------------------------------------------------
    # 1. verify every read against the latest committed version at start
    # ------------------------------------------------------------------
    invalid_reads = []
    read_checks = []
    for txn in txns:
        for step in txn["steps"]:
            if step["op"] != "read":
                continue
            key = step["key"]
            expected_writer = latest_before[txn["id"]].get(key, INITIAL_SENTINEL)
            expected_value = value_before[txn["id"]].get(
                key, initial.get(key)
            )
            observed = step["observed"]
            if isinstance(observed, dict):
                observed_writer = observed["writer"]
                observed_kind = "txn"
            else:
                observed_writer = INITIAL_SENTINEL
                observed_kind = "initial" if observed == INITIAL_SENTINEL else "literal"

            # A reader must name the expected writer; when it claims the
            # initial version we additionally compare the literal value.
            ok = observed_writer == expected_writer
            detail = {
                "transaction": txn["id"],
                "step": step["step_index"],
                "key": key,
                "expected_writer": expected_writer,
                "expected_value": expected_value,
                "observed_writer": observed_writer,
            }
            if observed_kind == "txn":
                # The named writer may exist structurally but never have
                # written this key: the claim is then impossible.
                claimed_value = _maybe_written_value(txns, observed_writer, key)
                if claimed_value is _MISSING:
                    ok = False
                    detail["observed_value"] = None
                    detail["note"] = (
                        f"{observed_writer!r} never wrote {key!r}"
                    )
                else:
                    detail["observed_value"] = claimed_value
            elif ok and observed_kind == "literal":
                ok = observed == expected_value
                detail["observed_value"] = observed
            elif ok and observed_kind == "initial":
                detail["observed_value"] = expected_value
            read_checks.append(detail)
            if not ok:
                invalid_reads.append(detail)

    if invalid_reads:
        return {
            "audit_id": norm["audit_id"],
            "status": "INVALID_READ",
            "invalid_reads": invalid_reads,
            "read_checks": read_checks,
            "transactions": [t["id"] for t in txns],
        }

    # ------------------------------------------------------------------
    # 2. construct the multi-version serialisation graph
    # ------------------------------------------------------------------
    # graph[src][dst] is a list of typed dependency edges (several keys can
    # produce parallel edges between the same ordered transaction pair).
    graph: dict[str, dict[str, list]] = {t["id"]: {} for t in txns}

    # 2a. write->write version-order edges, key by key, in commit order.
    ww_chains = {}
    for key, entries in writers_by_key.items():
        chain = [writer_id for _, writer_id, _ in entries]
        ww_chains[key] = chain
        for (_, prev, prev_step), (_, curr, curr_step) in zip(entries, entries[1:]):
            _add_edge(
                graph,
                prev,
                curr,
                {
                    "type": "ww",
                    "key": key,
                    "from_step": prev_step,
                    "to_step": curr_step,
                    "reason": (
                        f"both write {key!r}; version order follows commit "
                        f"time ({prev!r} at {txn_by_id[prev]['commit']}"
                        + (
                            f", tie broken by transaction id)"
                            if txn_by_id[prev]["commit"] == txn_by_id[curr]["commit"]
                            else f" before {curr!r} at {txn_by_id[curr]['commit']})"
                        )
                    ),
                },
            )

    # 2b. write->read dependency edges (a reader that observes a writer).
    for txn in txns:
        for step in txn["steps"]:
            if step["op"] != "read" or not isinstance(step["observed"], dict):
                continue
            writer = step["observed"]["writer"]
            _add_edge(
                graph,
                writer,
                txn["id"],
                {
                    "type": "wr",
                    "key": step["key"],
                    "from_step": _write_step_index(txns, writer, step["key"]),
                    "to_step": step["step_index"],
                    "reason": (
                        f"{txn['id']!r} reads {step['key']!r} installed by "
                        f"{writer!r}"
                    ),
                },
            )

    # 2c. read->write anti-dependency edges: a reader observes a version V
    # of key K while some committer C (C != V, C != reader) writes K; C must
    # be ordered either before V (already covered by ww/wr ordering) or after
    # the reader -> edge reader -> C.
    for txn in txns:
        for step in txn["steps"]:
            if step["op"] != "read":
                continue
            key = step["key"]
            observed_writer = (
                step["observed"]["writer"]
                if isinstance(step["observed"], dict)
                else INITIAL_SENTINEL
            )
            chain = ww_chains.get(key, [])
            for _, committer, write_step in writers_by_key.get(key, []):
                if committer == txn["id"]:
                    continue
                if observed_writer == INITIAL_SENTINEL:
                    # Every writer is newer than the initial version, unless
                    # it committed before the reader started -- but then the
                    # read could not legally observe the initial value.  The
                    # read was already validated, so here all writers are
                    # successors and must come after the reader.
                    before_reader = (
                        txn_by_id[committer]["commit"] < txn["start"]
                    )
                    if before_reader:
                        continue
                    edge_to = committer
                else:
                    if committer == observed_writer:
                        continue
                    try:
                        pos_obs = chain.index(observed_writer)
                    except ValueError:
                        pos_obs = -1
                    pos_committer = chain.index(committer)
                    if pos_committer <= pos_obs:
                        # older than or equal to the read version: ordering is
                        # fixed in the opposite direction by the version chain
                        continue
                    edge_to = committer

                _add_edge(
                    graph,
                    txn["id"],
                    edge_to,
                    {
                        "type": "rw",
                        "key": key,
                        "from_step": step["step_index"],
                        "to_step": write_step,
                        "reason": (
                            f"{txn['id']!r} reads {key!r} version from "
                            f"{observed_writer!r}; {edge_to!r} later writes "
                            f"{key!r}, so {edge_to!r} must follow the read"
                        ),
                    },
                )

    adjacency = {src: dict(dsts) for src, dsts in graph.items()}

    # ------------------------------------------------------------------
    # 3. decide acyclicity
    # ------------------------------------------------------------------
    order = _stable_topological_order(adjacency)
    if order is not None:
        return {
            "audit_id": norm["audit_id"],
            "status": "SERIALIZABLE",
            "serial_order": order,
            "read_checks": read_checks,
            "edges": _edges_payload(adjacency),
            "transactions": [t["id"] for t in txns],
            "recomputation": _recompute_serial(order, txns, initial),
        }

    cycle = _shortest_cycle(adjacency, txn_by_id)
    return {
        "audit_id": norm["audit_id"],
        "status": "NOT_SERIALIZABLE",
        "cycle": cycle,
        "read_checks": read_checks,
        "edges": _edges_payload(adjacency),
        "transactions": [t["id"] for t in txns],
    }


def _write_step_index(txns, writer_id, key):
    writer = next(t for t in txns if t["id"] == writer_id)
    for step in writer["steps"]:
        if step["op"] == "write" and step["key"] == key:
            return step["step_index"]
    raise RuntimeError("internal: missing write step")


def _edges_payload(adjacency):
    out = []
    for src in sorted(adjacency):
        for dst in sorted(adjacency[src]):
            for edge in adjacency[src][dst]:
                row = dict(edge)
                row["from"] = src
                row["to"] = dst
                out.append(row)
    return out


# ---------------------------------------------------------------------------
# Ordering decisions
# ---------------------------------------------------------------------------

def _stable_topological_order(adjacency):
    """Kahn's algorithm with a deterministic id tie-break.

    Returns ``None`` when the graph contains a cycle.
    """
    indegree = {node: 0 for node in adjacency}
    for src in adjacency:
        for dst in adjacency[src]:
            indegree[dst] += 1
    heap = [node for node, deg in indegree.items() if deg == 0]
    heapq.heapify(heap)
    order = []
    while heap:
        node = heapq.heappop(heap)
        order.append(node)
        for dst in sorted(adjacency[node]):
            indegree[dst] -= 1
            if indegree[dst] == 0:
                heapq.heappush(heap, dst)
    if len(order) != len(adjacency):
        return None
    return order


def _shortest_cycle(adjacency, txn_by_id):
    """Find a directed cycle with the minimum number of edges.

    Among minimum-length cycles, choose the one whose rotated vertex sequence
    (starting at its smallest transaction id) is lexicographically smallest --
    the verdict required by the specification.  Every edge is reported with
    its key, steps and version basis.
    """
    nodes = sorted(adjacency)
    best = None  # tuple(length, vertex-tuple-without-closing-repeat)

    # BFS from each source restricted to nodes >= source: every cycle is
    # considered exactly once, rooted at its smallest vertex -- which is
    # precisely the canonical rotation used for tie-breaking.
    for source in nodes:
        allowed = {n for n in nodes if n >= source}

        # Layered BFS; record every predecessor on a shortest path so that all
        # shortest return paths can be enumerated through the predecessor DAG.
        dist = {source: 0}
        predecessors = {source: []}
        frontier = [source]
        while frontier:
            next_frontier = []
            for node in frontier:
                for dst in adjacency[node]:
                    if dst not in allowed:
                        continue
                    nd = dist[node] + 1
                    if dst not in dist:
                        dist[dst] = nd
                        predecessors[dst] = [node]
                        next_frontier.append(dst)
                    elif dist[dst] == nd:
                        predecessors[dst].append(node)
            frontier = next_frontier

        # Closures: an edge u -> source closes a cycle of length dist[u] + 1.
        closers = [u for u in dist if source in adjacency[u]]
        if not closers:
            continue
        min_len = min(dist[u] + 1 for u in closers)
        closing = [u for u in closers if dist[u] + 1 == min_len]

        # Walk the predecessor DAG from each closing vertex back to source.
        stack = [(u, [u]) for u in sorted(closing, reverse=True)]
        while stack:
            node, rev_path = stack.pop()
            if node == source:
                forward = list(reversed(rev_path))  # source ... closer
                candidate = tuple(forward)
                if best is None or (min_len, candidate) < (best[0], best[1]):
                    best = (min_len, candidate)
                continue
            for pred in sorted(predecessors[node], reverse=True):
                stack.append((pred, rev_path + [pred]))

    if best is None:
        raise RuntimeError("internal: cycle expected but none found")

    length, vertices = best
    path = list(vertices) + [vertices[0]]
    edges = []
    for src, dst in zip(path, path[1:]):
        for edge in adjacency[src][dst]:
            row = dict(edge)
            row["from"] = src
            row["to"] = dst
            edges.append(row)
    return {
        "length": length,
        "vertices": list(vertices),
        "edges": edges,
        "reason": " -> ".join(path),
    }


# ---------------------------------------------------------------------------
# Serial recomputation: replay the winning order against the initial snapshot
# ---------------------------------------------------------------------------

def _recompute_serial(order, txns, initial):
    txn_by_id = {t["id"]: t for t in txns}
    store = dict(initial)
    per_txn = {}
    for txid in order:
        txn = txn_by_id[txid]
        local_store = dict(store)
        reads = []
        for step in txn["steps"]:
            if step["op"] == "read":
                value = local_store.get(step["key"])
                reads.append(
                    {
                        "step": step["step_index"],
                        "key": step["key"],
                        "value": value,
                    }
                )
            else:
                local_store[step["key"]] = step["value"]
        per_txn[txid] = reads
        store = local_store
    return {"final_state": store, "reads_in_order": per_txn}
