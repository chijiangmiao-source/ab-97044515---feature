"""Frozen audit-record store with durable, verifiable persistence.

An audit id, once frozen, is immutable for the lifetime of the service:

* re-submission of the *same* payload replays the stored verdict;
* submission of a *different* payload under the same id is rejected with
  ``409 CONFLICT`` and never overwrites the frozen record;
* concurrent submissions carrying the same payload collapse onto exactly
  one frozen record (the callers race under a single lock and the losers
  replay the winner's verdict).

Payload identity is compared over a canonical JSON encoding so that
formatting differences do not matter.

Durability
----------
When constructed with a log path, every first-time freeze is written as a
self-describing record::

    {"version":1,"audit_id":...,"fingerprint":...,"verdict":...,"checksum":"sha256:..."}

* the checksum covers the whole record except the ``checksum`` field, so a
  complete record that has been tampered with / torn on disk is detected;
* a record is committed only by its trailing newline; the file is replaced
  atomically (temp file + fsync + rename + directory fsync), so success is
  returned to the caller only after the full record is on platter;
* on start-up the log is replayed: committed lines rebuild the in-memory
  index, a trailing segment without the commit newline (an unfinished
  write left by a crash / power loss) is discarded and never becomes a
  readable verdict, while a *committed* line that fails verification marks
  the store unhealthy (``healthy`` is False) so ``/healthz`` fails loudly.

With ``path=None`` the store keeps records in memory only (tests, ephemeral
servers).
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import threading
from pathlib import Path

RECORD_VERSION = 1
FROZEN_STATUSES = {"SERIALIZABLE", "NOT_SERIALIZABLE"}
_CHECKSUM_ALGO = "sha256"
_AUDIT_ID_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def canonical_fingerprint(payload: dict) -> str:
    """Stable SHA-256 over the canonical JSON encoding of a payload."""
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _canonical_bytes(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _record_checksum(envelope: dict) -> str:
    return _CHECKSUM_ALGO + ":" + hashlib.sha256(_canonical_bytes(envelope)).hexdigest()


class ConflictError(Exception):
    def __init__(self, audit_id: str) -> None:
        super().__init__(f"audit_id {audit_id!r} is already frozen with a different payload")
        self.audit_id = audit_id


class RecordIntegrityError(Exception):
    """A *committed* log record fails verification, or a fresh durable
    write could not be verified on disk."""

    def __init__(self, reason: str, audit_id: str | None = None) -> None:
        where = f" for audit {audit_id!r}" if audit_id else ""
        super().__init__(f"frozen audit log integrity failed{where}: {reason}")
        self.reason = reason
        self.audit_id = audit_id


class FrozenStore:
    def __init__(self, path: str | os.PathLike | None = None) -> None:
        self._lock = threading.Lock()
        self._records: dict[str, dict] = {}
        self._path: Path | None = Path(path) if path is not None else None
        self._tmp_seq = 0
        self.healthy = True
        self.health_error: str | None = None
        self.dropped_tail_bytes = 0
        if self._path is not None:
            try:
                self._recover()
            except RecordIntegrityError as exc:
                # A committed record failed verification: stay constructable
                # so the HTTP layer can report an explicit unhealthy state;
                # no recovered verdict is served from a log that did not
                # fully check out.
                self.healthy = False
                self.health_error = str(exc)
                self._records = {}

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------
    def submit(self, payload: dict, verdict: dict) -> tuple[dict, bool]:
        """Freeze or replay.

        Returns ``(verdict, replayed)``.  ``replayed`` is True when an
        identical payload was already frozen.  Raises ``ConflictError``
        when the id exists but the payload differs, ``OSError`` when the
        durable write cannot be completed, and ``RecordIntegrityError``
        when the just-written record cannot be verified on disk.
        """
        audit_id = payload["audit_id"]
        fingerprint = canonical_fingerprint(payload)
        with self._lock:
            if not self.healthy:
                # Never rewrite or append to a log that failed verification:
                # doing so could hide the damaged committed record.
                raise RecordIntegrityError(
                    self.health_error or "audit log is unhealthy"
                )
            existing = self._records.get(audit_id)
            if existing is not None:
                if existing["fingerprint"] != fingerprint:
                    raise ConflictError(audit_id)
                return copy.deepcopy(existing["verdict"]), True
            record = {
                "version": RECORD_VERSION,
                "audit_id": audit_id,
                "fingerprint": fingerprint,
                "verdict": copy.deepcopy(verdict),
            }
            record["checksum"] = _record_checksum(record)
            if self._path is not None:
                self._write_durable(record)
            self._records[audit_id] = record
            return copy.deepcopy(verdict), False

    def get(self, audit_id: str) -> dict | None:
        with self._lock:
            existing = self._records.get(audit_id)
            return copy.deepcopy(existing) if existing else None

    def ids(self) -> list[str]:
        with self._lock:
            return sorted(self._records)

    # ------------------------------------------------------------------
    # recovery
    # ------------------------------------------------------------------
    def _fail(self, reason: str, audit_id: str | None = None) -> None:
        self.healthy = False
        self.health_error = reason
        raise RecordIntegrityError(reason, audit_id)

    def _recover(self) -> None:
        path = self._path
        assert path is not None
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                return
            data = path.read_bytes()
        except OSError as exc:
            self._fail(f"cannot read audit log {path}: {exc!r}")
            return

        # Remove temp files abandoned by crashes mid-write; they can never
        # be committed records.
        try:
            for tmp in path.parent.iterdir():
                if tmp.is_file() and tmp.name.startswith("." + path.name) and tmp.name.endswith(".tmp"):
                    tmp.unlink()
        except OSError:
            pass

        if not data:
            return
        committed = data.split(b"\n")
        if data.endswith(b"\n"):
            committed = committed[:-1]
            tail = b""
        else:
            # The final segment was never terminated: an unfinished write.
            # It is discarded regardless of how complete it looks.
            tail = committed.pop()

        recovered: dict[str, dict] = {}
        for line_no, line in enumerate(committed, start=1):
            if not line.strip():
                # A blank terminated line carries no record; ignore it.
                continue
            record = self._parse_committed(line, line_no)
            prior = recovered.get(record["audit_id"])
            if prior is not None and prior["fingerprint"] != record["fingerprint"]:
                self._fail(
                    f"two committed records for {record['audit_id']!r} carry "
                    f"different payload fingerprints (line {line_no})",
                    record["audit_id"],
                )
            # Identical duplicate: keep the first deterministically.
            recovered.setdefault(record["audit_id"], record)

        if tail.strip():
            # Reported but never fatal: no readable verdict is produced.
            self.dropped_tail_bytes = len(tail)
        self._records = recovered

    def _parse_committed(self, line: bytes, line_no: int) -> dict:
        try:
            obj = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._fail(f"committed record on line {line_no} is not valid JSON: {exc}")
        reason = self._validate_record(obj)
        if reason is not None:
            audit = obj.get("audit_id") if isinstance(obj, dict) else None
            self._fail(f"committed record on line {line_no} {reason}", audit)
        return obj  # type: ignore[return-value]

    @staticmethod
    def _validate_record(obj: object) -> str | None:
        """Return None when the record is complete and checks out, else a reason."""
        if not isinstance(obj, dict):
            return "is not a JSON object"
        if obj.get("version") != RECORD_VERSION:
            return f"has unsupported version {obj.get('version')!r}"
        audit_id = obj.get("audit_id")
        if not isinstance(audit_id, str) or not audit_id:
            return "is missing a non-empty audit_id"
        fingerprint = obj.get("fingerprint")
        if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            return "is missing a 64-hex-char fingerprint"
        verdict = obj.get("verdict")
        if not isinstance(verdict, dict) or not isinstance(verdict.get("status"), str):
            return "is missing a verdict with a string status"
        if verdict["status"] not in FROZEN_STATUSES:
            return f"carries an unfreezable verdict status {verdict['status']!r}"
        checksum = obj.get("checksum")
        if not isinstance(checksum, str) or not checksum.startswith(_CHECKSUM_ALGO + ":"):
            return "is missing its checksum"
        envelope = {k: v for k, v in obj.items() if k != "checksum"}
        if _record_checksum(envelope) != checksum:
            return "fails its checksum (the frozen record is corrupted)"
        return None

    # ------------------------------------------------------------------
    # durable write
    # ------------------------------------------------------------------
    def _write_durable(self, new_record: dict) -> None:
        path = self._path
        assert path is not None
        records = sorted(self._records.values(), key=lambda r: r["audit_id"])
        records.append(new_record)
        lines = [
            json.dumps(r, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            for r in records
        ]
        payload = ("\n".join(lines) + "\n").encode("utf-8")

        self._tmp_seq += 1
        slug = _AUDIT_ID_RE.sub("_", new_record["audit_id"])[:64] or "record"
        tmp_name = f".{path.name}.{os.getpid()}.{self._tmp_seq}.{slug}.tmp"
        tmp_path = path.parent / tmp_name
        fd = None
        try:
            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.write(fd, payload)
            os.fsync(fd)
            os.close(fd)
            fd = None
            os.replace(tmp_path, path)
            self._fsync_directory(path.parent)
        except OSError:
            if fd is not None:
                os.close(fd)
            try:
                tmp_path.unlink()
            except OSError:
                pass
            raise

        # The rename has landed and been fsynced; re-read the bytes and run
        # the same verification as recovery before reporting success.
        try:
            data = path.read_bytes()
        except OSError as exc:
            self._mark_unhealthy(f"fresh freeze for {new_record['audit_id']!r} could "
                                 f"not be read back: {exc!r}")
            raise RecordIntegrityError(str(exc), new_record["audit_id"]) from exc
        committed = data[:-1].split(b"\n") if data.endswith(b"\n") else []
        parsed = []
        for line_no, line in enumerate(committed, start=1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                self._mark_unhealthy(f"log unreadable after freeze, line {line_no}: {exc}")
                raise RecordIntegrityError(str(exc)) from exc
            reason = self._validate_record(obj)
            if reason is not None:
                self._mark_unhealthy(f"log fails verification after freeze, line {line_no}: {reason}")
                raise RecordIntegrityError(reason, obj.get("audit_id"))
            parsed.append(obj)
        if not any(r.get("audit_id") == new_record["audit_id"] for r in parsed):
            reason = "fresh freeze missing from the on-disk log after rename"
            self._mark_unhealthy(reason)
            raise RecordIntegrityError(reason, new_record["audit_id"])

    def _mark_unhealthy(self, reason: str) -> None:
        self.healthy = False
        self.health_error = reason

    @staticmethod
    def _fsync_directory(directory: Path) -> None:
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
