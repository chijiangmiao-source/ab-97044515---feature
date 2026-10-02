"""Durable frozen audit-record store.

An audit id, once frozen, is immutable for the lifetime of the service:

* re-submission of the *same* payload replays the stored verdict;
* submission of a *different* payload under the same id is rejected with
  ``409 CONFLICT`` and never overwrites the frozen record.

Payload identity is compared over a canonical JSON encoding so that
formatting differences do not matter.

Durability
----------
A freeze is reported as successful to the caller **only after** a
checksummed record has been appended to an on-disk journal and flushed
(fsync) through to the backing file.  Each committed record is one frame:

    F1\\n
    LEN <payload byte length>\\n
    <payload JSON bytes>
    SHA <sha-256 hex of the payload bytes>\\n
    END\\n

The trailing ``END`` line is the commit marker: it is written (and
fsynced) only after the whole checksummed body is on disk.  On startup
the journal is replayed:

* a frame whose bytes are incomplete (truncated header / body / SHA line
  / missing ``END``) is the *torn tail* of a write interrupted by a crash
  or power loss -- it is physically truncated and never forms a readable
    conclusion;
* a structurally complete frame with a bad checksum, bad JSON or a
  payload/fingerprint mismatch is a *corrupted existing record* -- even
  when it is the last frame -- and makes :meth:`health` fail explicitly;
* junk followed by another valid frame cannot be a torn tail (a live
  writer only ever appends complete frames at EOF) and is likewise
  corruption.

Every frame preceding the damaged area is still replayed into the index,
so confirmed serial orders / cycle evidence survive a restart.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import threading
from typing import Any

FRAME_MAGIC = b"F1\n"
_LEN_PREFIX = b"LEN "
_SHA_PREFIX = b"SHA "
_COMMIT_LINE = b"END\n"


def canonical_fingerprint(payload: dict) -> str:
    """Stable SHA-256 over the canonical JSON encoding of a payload."""
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


class ConflictError(Exception):
    def __init__(self, audit_id: str) -> None:
        super().__init__(f"audit_id {audit_id!r} is already frozen with a different payload")
        self.audit_id = audit_id


class JournalCorruptionError(Exception):
    """A complete, previously confirmed journal record was damaged."""

    def __init__(self, reason: str, offset: int) -> None:
        super().__init__(f"frozen-record journal corruption at byte {offset}: {reason}")
        self.reason = reason
        self.offset = offset


def _encode_record(record: dict) -> bytes:
    """Canonical byte encoding of one record (the checksummed body)."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _pack_frame(record: dict) -> tuple[bytes, bytes]:
    """Return ``(data, commit)``: checksummed frame body and commit marker.

    The writer must append + fsync ``data`` first, then append + fsync
    ``commit``.  A frame without its commit marker is an interrupted,
    torn write and is discarded on recovery.
    """
    body = _encode_record(record)
    digest = hashlib.sha256(body).hexdigest().encode("ascii")
    data = FRAME_MAGIC + _LEN_PREFIX + str(len(body)).encode("ascii") + b"\n" + body + b"\n" \
        + _SHA_PREFIX + digest + b"\n"
    return data, _COMMIT_LINE


def _validate_record(record: Any) -> None:
    """Reject bodies that cannot be genuine frozen records."""
    if not isinstance(record, dict):
        raise ValueError("record is not a JSON object")
    for key in ("audit_id", "fingerprint", "payload", "verdict"):
        if key not in record:
            raise ValueError(f"record missing field {key!r}")
    if not isinstance(record["audit_id"], str) or not record["audit_id"]:
        raise ValueError("record has invalid audit_id")
    if not isinstance(record["fingerprint"], str):
        raise ValueError("record has invalid fingerprint")
    if not isinstance(record["payload"], dict):
        raise ValueError("record has invalid payload")
    if canonical_fingerprint(record["payload"]) != record["fingerprint"]:
        raise ValueError("record fingerprint does not match payload")
    if not isinstance(record["verdict"], dict):
        raise ValueError("record has invalid verdict")


def _parse_frame(raw: bytes, pos: int) -> tuple[dict | None, int, str, bool]:
    """Try to parse one frame starting at ``pos``.

    Returns ``(record, next_pos, reason, structurally_complete)``:

    * ``record`` is non-None for a fully valid committed frame;
    * ``structurally_complete`` is True for a *committed* frame (its
      ``END`` marker is present) whose bytes / checksum / contents fail
      validation -- a corrupted existing record;
    * a frame without a commit marker is an interrupted (torn) write and
      is reported as incomplete, regardless of which part is missing;
    * ``reason`` describes the first failure.

    The checksummed body is one compact JSON line, so it can never contain
    a raw newline: the first ``"\\nEND\\n"`` after a frame's magic is
    unambiguously its commit marker.
    """
    total = len(raw)

    def fail(reason: str, complete: bool) -> tuple[None, int, str, bool]:
        return None, pos, reason, complete

    if not raw.startswith(FRAME_MAGIC, pos):
        return fail("missing frame magic", False)

    marker = raw.find(b"\n" + _COMMIT_LINE, pos + len(FRAME_MAGIC))
    if marker == -1:
        return fail("frame has no commit marker (interrupted write)", False)
    end_start = marker + 1  # index of the 'E' in END\n
    next_pos = end_start + len(_COMMIT_LINE)
    if next_pos > total:
        return fail("truncated commit marker", False)

    len_line_start = pos + len(FRAME_MAGIC)
    nl = raw.find(b"\n", len_line_start)
    if nl == -1 or nl >= end_start:
        return fail("malformed length line in committed frame", True)
    len_line = raw[len_line_start:nl]
    if not len_line.startswith(_LEN_PREFIX):
        return fail("malformed length line in committed frame", True)
    try:
        body_len = int(len_line[len(_LEN_PREFIX):])
        if body_len < 0:
            raise ValueError
    except ValueError:
        return fail("unparseable body length in committed frame", True)

    body_start = nl + 1
    body_end = body_start + body_len
    sha_start = body_end + 1
    if body_end >= total or raw[body_end:body_end + 1] != b"\n" or sha_start >= end_start:
        return fail("body/digest layout inconsistent in committed frame", True)
    sha_line = raw[sha_start:end_start - 1]  # byte before END is the '\n'
    if not sha_line.startswith(_SHA_PREFIX):
        return fail("malformed digest line in committed frame", True)

    body = raw[body_start:body_end]
    expected_digest = sha_line[len(_SHA_PREFIX):]
    if hashlib.sha256(body).hexdigest().encode("ascii") != expected_digest:
        return fail("payload checksum mismatch in committed frame", True)
    try:
        record = json.loads(body.decode("utf-8"))
        _validate_record(record)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return fail(f"invalid record contents in committed frame: {exc}", True)
    return record, next_pos, "", True


class FrozenStore:
    """In-memory audit index backed by an append-only durable journal."""

    def __init__(self, path: str | os.PathLike[str] | None = None) -> None:
        self._lock = threading.RLock()
        self._records: dict[str, dict] = {}
        self._path = os.fspath(path) if path is not None else None
        self._file = None
        self._healthy = True
        self._health_reason = ""
        self._replayed = 0
        self._torn_tail_discarded = False
        if self._path is not None:
            self._open_and_recover()

    # ------------------------------------------------------------------
    # startup / recovery
    # ------------------------------------------------------------------
    def _open_and_recover(self) -> None:
        assert self._path is not None
        parent = os.path.dirname(os.path.abspath(self._path))
        os.makedirs(parent, exist_ok=True)
        existed = os.path.exists(self._path)
        self._recover_journal()
        # O_APPEND positions every write at the current EOF atomically, so
        # a frame can never be spliced into the middle of another frame.
        self._file = open(self._path, "ab", buffering=0)
        if not existed:
            self._fsync_dir(parent)

    @staticmethod
    def _fsync_dir(directory: str) -> None:
        try:
            fd = os.open(directory, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(fd)
        except OSError:
            pass
        finally:
            os.close(fd)

    def _recover_journal(self) -> None:
        try:
            with open(self._path, "rb") as fh:
                raw = fh.read()
        except FileNotFoundError:
            return
        except OSError as exc:
            self._fail_health(f"journal unreadable: {exc}")
            return

        loaded: dict[str, dict] = {}
        pos = 0
        good_end = 0
        total = len(raw)
        while pos < total:
            record, next_pos, reason, complete = _parse_frame(raw, pos)
            if record is not None:
                loaded[record["audit_id"]] = record
                good_end = next_pos
                pos = next_pos
                continue

            if complete:
                # All bytes of the frame are present, yet its checksum or
                # contents are bad: a confirmed record was corrupted.
                self._adopt_loaded(loaded)
                self._fail_health(reason, pos)
                return

            # The frame looks incomplete.  It is a torn tail only if no
            # valid frame exists later in the file.
            later = self._find_later_valid_frame(raw, pos + 1)
            if later != -1:
                self._adopt_loaded(loaded)
                self._fail_health(f"{reason} (a valid frame follows byte {pos})", pos)
                return

            # Genuine torn tail: discard everything after the last good
            # frame physically, so an O_APPEND writer never extends the
            # half-written frame.
            self._torn_tail_discarded = True
            try:
                with open(self._path, "r+b") as fh:
                    fh.truncate(good_end)
                    fh.flush()
                    os.fsync(fh.fileno())
            except OSError as exc:
                self._adopt_loaded(loaded)
                self._fail_health(f"cannot discard torn tail: {exc}", pos)
                return
            break

        self._adopt_loaded(loaded)

    @staticmethod
    def _find_later_valid_frame(raw: bytes, start: int) -> int:
        """Offset of a valid committed frame at or after ``start`` else -1."""
        probe = start
        while True:
            probe = raw.find(FRAME_MAGIC, probe)
            if probe == -1:
                return -1
            record, _, _, _ = _parse_frame(raw, probe)
            if record is not None:
                return probe
            probe += 1

    def _adopt_loaded(self, loaded: dict[str, dict]) -> None:
        self._records = loaded
        self._replayed = len(loaded)

    def _fail_health(self, reason: str, offset: int = -1) -> None:
        self._healthy = False
        self._health_reason = (
            f"journal corruption at byte {offset}: {reason}" if offset >= 0 else reason
        )

    # ------------------------------------------------------------------
    # freeze / replay
    # ------------------------------------------------------------------
    def submit(self, payload: dict, verdict: dict) -> tuple[dict, bool]:
        """Freeze or replay.

        Returns ``(verdict, replayed)``.  ``replayed`` is True when an
        identical payload was already frozen.  Raises ``ConflictError``
        when the id exists but the payload fingerprint differs.

        A first freeze returns success only after the complete
        checksummed frame *and* its commit marker have been fsynced.
        """
        audit_id = payload["audit_id"]
        fingerprint = canonical_fingerprint(payload)
        with self._lock:
            existing = self._records.get(audit_id)
            if existing is not None:
                if existing["fingerprint"] != fingerprint:
                    raise ConflictError(audit_id)
                return copy.deepcopy(existing["verdict"]), True

            record = {
                "audit_id": audit_id,
                "fingerprint": fingerprint,
                "payload": copy.deepcopy(payload),
                "verdict": copy.deepcopy(verdict),
            }
            data, commit = _pack_frame(record)
            self._append_durable(data)
            self._append_durable(commit)
            self._records[audit_id] = record
            return copy.deepcopy(verdict), False

    def _append_durable(self, chunk: bytes) -> None:
        if self._file is None:
            return  # in-memory mode
        try:
            self._file.write(chunk)
            self._file.flush()
            os.fsync(self._file.fileno())
        except OSError as exc:
            self._fail_health(f"journal append failed: {exc}")
            raise

    def get(self, audit_id: str) -> dict | None:
        with self._lock:
            existing = self._records.get(audit_id)
            return copy.deepcopy(existing) if existing else None

    def ids(self) -> list[str]:
        with self._lock:
            return sorted(self._records)

    def health(self) -> tuple[bool, str]:
        """``(healthy, reason)`` -- unhealthy on corruption or I/O failure."""
        with self._lock:
            return self._healthy, self._health_reason

    def stats(self) -> dict:
        with self._lock:
            return {
                "records": len(self._records),
                "replayed": self._replayed,
                "torn_tail_discarded": self._torn_tail_discarded,
                "durable": self._path is not None,
            }

    def close(self) -> None:
        with self._lock:
            if self._file is not None:
                try:
                    self._file.flush()
                    os.fsync(self._file.fileno())
                except OSError:
                    pass
                finally:
                    self._file.close()
                    self._file = None
