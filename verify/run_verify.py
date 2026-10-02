#!/usr/bin/env python3
"""One-shot acceptance service.

Runs, in order:

  1. code tests              -- unittest suite under /app/verify/tests
  2. differential fuzz       -- analyser vs an independent oracle
  3. image build check       -- builds the project image through the Docker
                                Engine API on /var/run/docker.sock (no docker
                                CLI / pip packages needed)
  4. HTTP smoke              -- exercises the real web service end to end
  5. durable restart         -- freezes records, hard-kills the web
                                container (power loss), and verifies the
                                journal replay: same verdict replay, payload
                                conflicts, torn-tail discard and explicit
                                health failure on a corrupted record

Exits 0 only when every check passes; each failing check contributes to a
non-zero exit code so CI / `docker compose run` observe the verdict.
"""

from __future__ import annotations

import io
import json
import os
import socket
import subprocess
import sys
import tarfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_ROOT = os.environ.get("APP_ROOT", "/app" if os.path.isdir("/app/verify") else _REPO_ROOT)
PROJECT_ROOT = os.environ.get("PROJECT_ROOT", "/workspace" if os.path.isdir("/workspace/src") else _REPO_ROOT)
SOCK_PATH = os.environ.get("DOCKER_SOCK", "/var/run/docker.sock")
SMOKE_TARGET = os.environ.get("SMOKE_TARGET", "http://web:8080")
IMAGE_TAG = os.environ.get("VERIFY_IMAGE_TAG", "mvscc-audit:verify-built")
WEB_CONTAINER = os.environ.get("WEB_CONTAINER", "mvscc-web")
JOURNAL_IN_CONTAINER = os.environ.get("JOURNAL_IN_CONTAINER", "/data/frozen.journal")

# Reuse the real frame parser so the restart stage counts committed frames
# exactly the way the service's recovery does.
sys.path.insert(0, os.path.join(APP_ROOT, "src") if os.path.isdir(
    os.path.join(APP_ROOT, "src")) else os.path.join(_REPO_ROOT, "src"))
from store import _parse_frame  # noqa: E402

results = []


def record(name, ok, detail=""):
    results.append((name, ok, detail))
    mark = "PASS" if ok else "FAIL"
    line = f"[{mark}] {name}"
    if detail:
        line += f"  -- {detail}"
    print(line, flush=True)


# ---------------------------------------------------------------------------
# 1. code tests
# ---------------------------------------------------------------------------

def run_code_tests() -> bool:
    loader = unittest.TestLoader()
    suite = loader.discover(os.path.join(APP_ROOT, "verify", "tests"), pattern="test_*.py")
    stream = io.StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=2)
    print("\n=== 1/5 code tests ===", flush=True)
    test_result = runner.run(suite)
    print(stream.getvalue())
    ok = test_result.wasSuccessful()
    record(
        "code tests",
        ok,
        f"{test_result.testsRun} tests, "
        f"{len(test_result.failures)} failures, {len(test_result.errors)} errors",
    )
    return ok


def run_differential_fuzz() -> bool:
    """Cross-check the analyser against an independent oracle (DFS cycle
    test + exhaustive simple-cycle enumeration on random histories)."""
    print("\n=== 2/5 differential fuzz ===", flush=True)
    script = os.path.join(APP_ROOT, "verify", "fuzz_oracle.py")
    try:
        proc = subprocess.run(
            [sys.executable, script], capture_output=True, text=True, timeout=120
        )
    except (OSError, subprocess.SubprocessError) as exc:
        record("differential fuzz", False, repr(exc))
        return False
    print(proc.stdout)
    if proc.stderr.strip():
        print(proc.stderr, file=sys.stderr)
    ok = proc.returncode == 0
    record("differential fuzz", ok, proc.stdout.strip().splitlines()[-1] if ok else proc.stderr[-300:])
    return ok


# ---------------------------------------------------------------------------
# 2. image build check over the Docker Engine UNIX socket
# ---------------------------------------------------------------------------

def _docker_raw_request(method: str, path: str, body: bytes = b"",
                        content_type: str | None = None, timeout: int = 180,
                        extra_headers: list[tuple[str, str]] | None = None) -> tuple[dict, bytes]:
    headers = [f"{method} {path} HTTP/1.1", "Host: docker"]
    if body:
        headers += [f"Content-Type: {content_type or 'application/octet-stream'}",
                    f"Content-Length: {len(body)}"]
    for key, value in extra_headers or []:
        headers.append(f"{key}: {value}")
    headers += ["Connection: close", "", ""]
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect(SOCK_PATH)
    sock.sendall(("\r\n".join(headers)).encode() + body)
    chunks = []
    while True:
        data = sock.recv(65536)
        if not data:
            break
        chunks.append(data)
    sock.close()
    raw = b"".join(chunks)
    head, _, payload = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status_code = int(lines[0].split()[1])
    parsed = {}
    for line in lines[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            parsed[k.strip().lower()] = v.strip()
    if parsed.get(b"transfer-encoding") == b"chunked":
        payload = _dechunk(payload)
    elif b"content-length" in parsed:
        payload = payload[: int(parsed[b"content-length"])]
    return {"status": status_code, "headers": parsed}, payload


def _docker_api_build(context_dir: str, tag: str) -> tuple[bool, str]:
    """POST a tar build context to the Docker daemon via HTTP/1.1."""
    buf = io.BytesIO()
    excludes = {".git", "__pycache__", ".pytest_cache"}
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for root, dirs, files in os.walk(context_dir):
            dirs[:] = [d for d in dirs if d not in excludes]
            for name in files:
                if name.endswith((".pyc", ".pyo")):
                    continue
                full = os.path.join(root, name)
                arc = os.path.relpath(full, context_dir)
                tar.add(full, arcname=arc)
    context = buf.getvalue()

    # Negotiate the API version: prefer a pinned recent one, then whatever the
    # daemon supports, finally a version-less request.
    api_versions = []
    try:
        meta, raw_version = _docker_raw_request("GET", "/version", timeout=10)
        if meta["status"] == 200:
            info = json.loads(raw_version.decode())
            if info.get("ApiVersion"):
                api_versions.append("/v" + info["ApiVersion"])
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    api_versions += ["/v1.43", ""]

    last = "no API version accepted"
    for prefix in api_versions:
        path = f"{prefix}/build?dockerfile=Dockerfile&t={tag}"
        meta, body = _docker_raw_request(
            "POST", path, body=context,
            content_type="application/x-tar",
        )
        if meta["status"] not in (200, 201):
            last = f"HTTP {meta['status']}: {body[:300].decode(errors='replace')}"
            # 400 here usually means an unsupported API version -> retry.
            if meta["status"] == 400:
                continue
            return False, last
        last = ""
        break
    if last:
        return False, last
    # The build stream is newline-delimited JSON; a failing build carries an
    # "error" field even when the HTTP status is 200.
    saw_error = None
    streamed = []
    for line in body.decode(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "error" in event:
            saw_error = event["error"]
        if "stream" in event:
            streamed.append(event["stream"].rstrip())
    tail = " | ".join(streamed[-3:])
    if saw_error:
        return False, saw_error
    return True, f"image {tag} built; {tail}"


def _dechunk(buf: bytes) -> bytes:
    out = io.BytesIO()
    pos = 0
    while True:
        end = buf.find(b"\r\n", pos)
        if end == -1:
            break
        size_text = buf[pos:end].split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError:
            break
        pos = end + 2
        if size == 0:
            break
        out.write(buf[pos:pos + size])
        pos += size + 2
    return out.getvalue()


def run_image_build_check() -> bool:
    print("\n=== 3/5 image build check ===", flush=True)
    dockerfile = os.path.join(PROJECT_ROOT, "Dockerfile")
    if not os.path.exists(SOCK_PATH):
        record("image build check", False, f"Docker socket {SOCK_PATH} not available")
        return False
    if not os.path.exists(dockerfile):
        record("image build check", False, f"build context missing at {PROJECT_ROOT}")
        return False
    try:
        ok, detail = _docker_api_build(PROJECT_ROOT, IMAGE_TAG)
    except (OSError, socket.timeout) as exc:
        ok, detail = False, f"daemon communication failed: {exc!r}"
    record("image build check", ok, detail)
    return ok


# ---------------------------------------------------------------------------
# 3. HTTP smoke against the real service
# ---------------------------------------------------------------------------

SERIAL_PAYLOAD = {
    "audit_id": "smoke-serial",
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
STALE_PAYLOAD = {
    "audit_id": "smoke-stale",
    "initial": {"x": 0},
    "transactions": [
        {"id": "T1", "start": 1, "commit": 5, "steps": [
            {"op": "write", "key": "x", "value": 10}]},
        {"id": "T2", "start": 6, "commit": 8, "steps": [
            {"op": "read", "key": "x", "observed": "initial"}]},
    ],
}
SKEW_PAYLOAD = {
    "audit_id": "smoke-skew",
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


def http(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(SMOKE_TARGET + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read().decode()
            return resp.status, dict(resp.headers), (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        return exc.code, dict(exc.headers), (json.loads(raw) if raw else None)


def run_http_smoke() -> bool:
    print("\n=== 4/5 HTTP smoke ===", flush=True)
    all_ok = True

    def expect(name, cond, detail=""):
        nonlocal all_ok
        record(name, cond, detail)
        all_ok = all_ok and cond

    for attempt in range(12):
        try:
            status, _, body = http("GET", "/healthz")
            if status == 200:
                break
        except (urllib.error.URLError, ConnectionError):
            pass
        time.sleep(2)
    else:
        expect("health endpoint reachable", False, f"{SMOKE_TARGET}/healthz never answered")
        return False
    expect("health endpoint reachable", True, f"{SMOKE_TARGET}/healthz -> {body}")

    try:
        with urllib.request.urlopen(SMOKE_TARGET + "/", timeout=10) as resp:
            page = resp.read().decode()
            page_status = resp.status
        expect("console page served", page_status == 200 and "多版本" in page, f"GET / -> {page_status}")
    except Exception as exc:  # noqa: BLE001
        expect("console page served", False, repr(exc))

    status, headers, body = http("POST", "/api/audits", SERIAL_PAYLOAD)
    expect("serializable history frozen", status == 201 and body["status"] == "SERIALIZABLE"
           and body["serial_order"] == ["T1", "T2"],
           f"POST -> {status} {body.get('status') if body else body}")
    expect("serial order recomputed reads",
           body and body["recomputation"]["final_state"] == {"x": 3},
           f"final_state={body and body['recomputation']['final_state']}")

    status, headers, body = http("POST", "/api/audits", SERIAL_PAYLOAD)
    expect("identical payload replays verdict",
           status == 200 and headers.get("X-Audit-Replayed") == "true",
           f"POST replay -> {status}")

    changed = json.loads(json.dumps(SERIAL_PAYLOAD))
    changed["initial"]["x"] = 999
    status, _, body = http("POST", "/api/audits", changed)
    expect("changed payload under frozen id rejected",
           status == 409 and body["error"] == "AUDIT_ID_CONFLICT",
           f"POST changed -> {status}")

    status, _, body = http("GET", "/api/audits/smoke-serial")
    expect("frozen record fetchable and intact",
           status == 200 and body["serial_order"] == ["T1", "T2"],
           f"GET -> {status}")

    status, _, body = http("POST", "/api/audits", STALE_PAYLOAD)
    expect("stale version read reported as input error",
           status == 422 and body["error"] == "STALE_VERSION_READ"
           and body["verdict"]["invalid_reads"][0]["transaction"] == "T2",
           f"POST stale -> {status}")

    status, _, body = http("POST", "/api/audits", SKEW_PAYLOAD)
    cycle = body.get("cycle") if body else None
    expect("write skew reported as shortest cycle",
           status == 201 and body["status"] == "NOT_SERIALIZABLE"
           and cycle and cycle["length"] == 2
           and {e["type"] for e in cycle["edges"]} == {"rw"}
           and all(e["key"] for e in cycle["edges"]),
           f"POST skew -> {status}, cycle={cycle and cycle['vertices']}")

    status, _, body = http("GET", "/api/audits/no-such-id")
    expect("unknown audit -> 404", status == 404, f"GET missing -> {status}")

    return all_ok


# ---------------------------------------------------------------------------
# 4. durable restart acceptance (real container kill + journal replay)
# ---------------------------------------------------------------------------

ACC_SERIAL = json.loads(json.dumps(SERIAL_PAYLOAD))
ACC_SERIAL["audit_id"] = "acc-restart-serial"
ACC_SKEW = json.loads(json.dumps(SKEW_PAYLOAD))
ACC_SKEW["audit_id"] = "acc-restart-skew"
ACC_RACE = json.loads(json.dumps(SERIAL_PAYLOAD))
ACC_RACE["audit_id"] = "acc-restart-race"
JOURNAL_DIR = os.path.dirname(JOURNAL_IN_CONTAINER)
JOURNAL_NAME = os.path.basename(JOURNAL_IN_CONTAINER)


def _docker_json(method, path, body=None, content_type=None, timeout=60):
    meta, raw = _docker_raw_request(
        method, path, body=body or b"", content_type=content_type, timeout=timeout
    )
    parsed = None
    if raw:
        try:
            parsed = json.loads(raw.decode(errors="replace"))
        except json.JSONDecodeError:
            parsed = None
    return meta["status"], parsed


def _find_web_container():
    status, containers = _docker_json("GET", "/containers/json?all=1")
    if status != 200 or not isinstance(containers, list):
        return None
    for c in containers:
        if any(name.lstrip("/") == WEB_CONTAINER for name in c.get("Names", [])):
            return c["Id"]
    return None


def _container_state(cid):
    status, info = _docker_json("GET", f"/containers/{cid}/json")
    if status != 200 or not info:
        return "unknown"
    return info.get("State", {}).get("status", "unknown")


def _set_restart_policy(cid, name):
    _docker_json("POST", f"/containers/{cid}/update",
                 body=json.dumps({"RestartPolicy": {"Name": name}}).encode(),
                 content_type="application/json")


def _kill_container(cid):
    _docker_json("POST", f"/containers/{cid}/kill")
    for _ in range(30):
        if _container_state(cid) in ("exited", "dead", "created"):
            return True
        time.sleep(0.3)
    return False


def _start_container(cid):
    _docker_json("POST", f"/containers/{cid}/start")


def _download_journal(cid):
    """Pull the journal out of the (stopped) container as raw bytes."""
    meta, raw = _docker_raw_request(
        "GET", f"/containers/{cid}/archive?path={urllib.parse.quote(JOURNAL_DIR)}",
        timeout=60,
    )
    if meta["status"] != 200:
        raise RuntimeError(f"journal download HTTP {meta['status']}: {raw[:200]!r}")
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as tar:
        member = None
        for m in tar.getmembers():
            if m.isfile() and os.path.basename(m.name) == JOURNAL_NAME:
                member = m
                break
        if member is None:
            raise RuntimeError("frozen journal not found in container archive")
        return tar.extractfile(member).read()


def _upload_journal(cid, journal_bytes):
    """Replace the journal inside the (stopped) container filesystem."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name=JOURNAL_NAME)
        info.size = len(journal_bytes)
        info.mtime = int(time.time())
        tar.addfile(info, io.BytesIO(journal_bytes))
    status, _ = _docker_json(
        "PUT",
        f"/containers/{cid}/archive?path={urllib.parse.quote(JOURNAL_DIR)}"
        "&noOverwriteDirNonDir=false",
        body=buf.getvalue(), content_type="application/x-tar", timeout=60,
    )
    if status not in (200, 201):
        raise RuntimeError(f"journal upload HTTP {status}")


def _wait_web_health(expected=200, attempts=30):
    last = None
    for _ in range(attempts):
        try:
            status, _, body = http("GET", "/healthz")
            last = (status, body)
            if status == expected:
                return status, body
        except (urllib.error.URLError, ConnectionError, json.JSONDecodeError) as exc:
            last = ("unreachable", repr(exc))
        time.sleep(1)
    return None if last is None else last


def _torn_tail_bytes(good_bytes):
    """A half-written trailing frame: checksummed body present, END absent."""
    return good_bytes + b"F1\nLEN 120\n{\"audit_id\": \"acc-torn-tail\", \"partial\": true"


def _corrupt_last_committed_frame(good_bytes):
    """Flip one byte inside the last committed frame's JSON body.

    Its ``END\\n`` marker is preserved, so recovery must classify this as
    a corrupted *complete* record (checksum mismatch), not a torn write.
    """
    last_magic = good_bytes.rfind(b"F1\n")
    body_start = good_bytes.find(b"{", last_magic)
    if body_start == -1:
        raise RuntimeError("no JSON body found in last journal frame")
    flipped = (good_bytes[body_start] ^ 0x01).to_bytes(1, "little")
    return good_bytes[:body_start] + flipped + good_bytes[body_start + 1:]


def run_durable_restart_acceptance() -> bool:
    print("\n=== 5/5 durable restart acceptance (power-loss replay) ===", flush=True)
    all_ok = True

    def expect(name, cond, detail=""):
        nonlocal all_ok
        record(name, cond, detail)
        all_ok = all_ok and cond

    if not os.path.exists(SOCK_PATH):
        expect("docker daemon available for restart test", False,
               f"{SOCK_PATH} missing")
        return False

    cid = _find_web_container()
    expect("locate running web container", cid is not None, WEB_CONTAINER)
    if not cid:
        return False

    # ---- freeze records through the real HTTP API ---------------------
    status, _, created = http("POST", "/api/audits", ACC_SERIAL)
    expect("created record freezes (201)", status == 201,
           f"POST -> {status}")
    status, headers, replayed = http("POST", "/api/audits", ACC_SERIAL)
    expect("conflict-free retransmission replays (200)",
           status == 200 and headers.get("X-Audit-Replayed") == "true"
           and replayed == created, f"POST replay -> {status}")
    changed = json.loads(json.dumps(ACC_SERIAL))
    changed["initial"]["x"] = 777
    status, _, body = http("POST", "/api/audits", changed)
    expect("changed payload under same id conflicts (409)",
           status == 409 and body and body["error"] == "AUDIT_ID_CONFLICT",
           f"POST changed -> {status}")
    status, _, skew_created = http("POST", "/api/audits", ACC_SKEW)
    expect("cycle evidence record freezes (201)",
           status == 201 and skew_created
           and skew_created.get("status") == "NOT_SERIALIZABLE",
           f"POST skew -> {status}")

    # ---- concurrent identical submissions must freeze exactly once ----
    race_statuses = []
    race_lock = threading.Lock()

    def post_race():
        req = urllib.request.Request(
            SMOKE_TARGET + "/api/audits",
            data=json.dumps(ACC_RACE).encode(), method="POST")
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                code = resp.status
        except urllib.error.HTTPError as exc:  # pragma: no cover
            code = exc.code
        with race_lock:
            race_statuses.append(code)

    threads = [threading.Thread(target=post_race) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    expect("concurrent identical posts: exactly one 201, rest replay 200",
           race_statuses.count(201) == 1 and race_statuses.count(200) == 7,
           str(sorted(race_statuses)))

    # ---- hard kill + torn tail + restart -------------------------------
    good_bytes = None
    try:
        _set_restart_policy(cid, "no")
        killed = _kill_container(cid)
        expect("SIGKILL web container (simulated power loss)", killed,
               f"state={_container_state(cid)}")
        good_bytes = _download_journal(cid)

        def frame_ids(blob):
            ids, pos = [], 0
            while True:
                record, next_pos, _reason, _complete = _parse_frame(blob, pos)
                if record is None:
                    break
                ids.append(record["audit_id"])
                pos = next_pos
            return ids

        frozen_ids = frame_ids(good_bytes)
        unique_ids = set(frozen_ids)
        expect("journal holds one committed frame per distinct freeze",
               len(frozen_ids) == len(unique_ids)
               and {"acc-restart-serial", "acc-restart-skew", "acc-restart-race"}
               <= unique_ids,
               f"frames={frozen_ids}")

        _upload_journal(cid, _torn_tail_bytes(good_bytes))
        _start_container(cid)
        got = _wait_web_health(200)
        expect("service healthy after discarding torn tail",
               bool(got) and got[0] == 200, str(got)[:160])

        status, _, body = http("GET", "/api/audits/acc-torn-tail")
        expect("torn tail never forms a readable conclusion",
               status == 404, f"GET torn -> {status}")
        status, _, body = http("GET", "/api/audits/acc-restart-serial")
        expect("recovered serial conclusion is intact",
               status == 200 and body == created, f"GET -> {status}")
        status, _, body = http("GET", "/api/audits/acc-restart-skew")
        expect("recovered cycle conclusion is intact",
               status == 200 and body == skew_created, f"GET -> {status}")
        status, headers, body = http("POST", "/api/audits", ACC_SERIAL)
        expect("same id+payload replays original after restart",
               status == 200 and headers.get("X-Audit-Replayed") == "true"
               and body == created, f"POST replay -> {status}")
        status, _, body = http("POST", "/api/audits", changed)
        expect("changed payload still conflicts after restart",
               status == 409 and body["error"] == "AUDIT_ID_CONFLICT",
               f"POST changed -> {status}")

        # ---- hard kill + corrupted *committed* record + restart --------
        if not _kill_container(cid):
            expect("SIGKILL before corruption injection", False,
                   f"state={_container_state(cid)}")
        else:
            _upload_journal(cid, _corrupt_last_committed_frame(good_bytes))
            _start_container(cid)
            got = _wait_web_health(503)
            expect("corrupted complete record fails health explicitly",
                   bool(got) and got[0] == 503
                   and isinstance(got[1], dict)
                   and got[1].get("error") == "JOURNAL_CORRUPT",
                   str(got)[:200])
            # undamaged prefix is still readable
            status, _, body = http("GET", "/api/audits/acc-restart-serial")
            expect("undamaged prefix still served while unhealthy",
                   status == 200 and body == created, f"GET -> {status}")

            # ---- restore a clean journal so the environment is left ok -
            _kill_container(cid)
            _upload_journal(cid, good_bytes)
            _start_container(cid)
            got = _wait_web_health(200)
            expect("health restored after clean journal reinstated",
                   bool(got) and got[0] == 200, str(got)[:160])
    except Exception as exc:  # noqa: BLE001 - acceptance reports the failure
        expect("durable restart stage completed without tooling error",
               False, repr(exc))
    finally:
        # Never leave the shared web container stopped, unhealthy, or
        # holding a deliberately corrupted journal: reinstate the pristine
        # copy captured before any damage was injected.
        try:
            if good_bytes is not None:
                if _container_state(cid) == "running":
                    _kill_container(cid)
                try:
                    _upload_journal(cid, good_bytes)
                except Exception:  # noqa: BLE001
                    pass
                if _container_state(cid) != "running":
                    _start_container(cid)
            elif _container_state(cid) != "running":
                _start_container(cid)
            _set_restart_policy(cid, "unless-stopped")
        except Exception:  # noqa: BLE001
            pass
        _wait_web_health(200, attempts=15)

    return all_ok


def main() -> int:
    print(f"mvscc verify: target={SMOKE_TARGET} project={PROJECT_ROOT}", flush=True)
    ok_tests = run_code_tests()
    ok_fuzz = run_differential_fuzz()
    ok_image = run_image_build_check()
    ok_smoke = run_http_smoke()
    ok_restart = run_durable_restart_acceptance()

    print("\n=== acceptance summary ===")
    for name, ok, _ in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    code = 0 if (ok_tests and ok_fuzz and ok_image and ok_smoke and ok_restart) else 1
    print(f"\nverify exit code: {code}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
