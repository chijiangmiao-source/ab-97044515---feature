#!/usr/bin/env python3
"""One-shot acceptance service.

Runs, in order:

  1. code tests            -- unittest suite under /app/verify/tests
  2. image build check     -- builds the project image through the Docker
                              Engine API on /var/run/docker.sock (no docker
                              CLI / pip packages needed)
  3. HTTP smoke            -- exercises the real web service end to end
  4. restart durability    -- freezes records, restarts the web container
                              through the Engine API, replays verdicts /
                              conflicts, drops an unfinished tail, then
                              corrupts a committed record and demands a
                              failed health check

Exits 0 only when every check passes; each failing check contributes to a
non-zero exit code so CI / `docker compose run` observe the verdict.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tarfile
import time
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_ROOT = os.environ.get("APP_ROOT", "/app" if os.path.isdir("/app/verify") else _REPO_ROOT)
PROJECT_ROOT = os.environ.get("PROJECT_ROOT", "/workspace" if os.path.isdir("/workspace/src") else _REPO_ROOT)
SOCK_PATH = os.environ.get("DOCKER_SOCK", "/var/run/docker.sock")
SMOKE_TARGET = os.environ.get("SMOKE_TARGET", "http://web:8080")
IMAGE_TAG = os.environ.get("VERIFY_IMAGE_TAG", "mvscc-audit:verify-built")

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
                        content_type: str | None = None, timeout: int = 180) -> tuple[dict, bytes]:
    headers = [f"{method} {path} HTTP/1.1", "Host: docker"]
    if body:
        headers += [f"Content-Type: {content_type or 'application/octet-stream'}",
                    f"Content-Length: {len(body)}"]
    elif method in ("POST", "PUT"):
        headers.append("Content-Length: 0")
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
    excludes = {".git", "__pycache__", ".pytest_cache", "data"}
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
# 2b. Docker Engine API: locate / restart the real web container
# ---------------------------------------------------------------------------

_api_prefix_cache: str | None = None


def _api_prefix() -> str:
    global _api_prefix_cache
    if _api_prefix_cache is not None:
        return _api_prefix_cache
    try:
        meta, raw = _docker_raw_request("GET", "/version", timeout=10)
        if meta["status"] == 200 and json.loads(raw.decode()).get("ApiVersion"):
            _api_prefix_cache = "/v" + json.loads(raw.decode())["ApiVersion"]
            return _api_prefix_cache
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    _api_prefix_cache = "/v1.43"
    return _api_prefix_cache


def _find_web_container() -> str | None:
    """Return the container id of the compose ``web`` service."""
    wanted = os.environ.get("WEB_CONTAINER", "mvscc-web")
    meta, raw = _docker_raw_request(
        "GET", _api_prefix() + "/containers/json?all=1", timeout=10
    )
    if meta["status"] != 200:
        return None
    containers = json.loads(raw.decode())
    # exact container name first (other compose projects may also have a
    # service called "web")
    for c in containers:
        if f"/{wanted}" in (c.get("Names") or []):
            return c["Id"]
    for c in containers:
        if (c.get("Labels") or {}).get("com.docker.compose.service") == "web":
            return c["Id"]
    return None


def _restart_web_container(cid: str) -> tuple[bool, str]:
    meta, raw = _docker_raw_request(
        "POST", f"{_api_prefix()}/containers/{cid}/restart?t=1",
        body=b"", content_type="application/json", timeout=30,
    )
    if meta["status"] not in (204, 304):
        return False, f"restart -> HTTP {meta['status']}: {raw[:200].decode(errors='replace')}"
    return True, "restarted"


def _stop_web_container(cid: str) -> tuple[bool, str]:
    meta, raw = _docker_raw_request(
        "POST", f"{_api_prefix()}/containers/{cid}/stop?t=3",
        body=b"", content_type="application/json", timeout=30,
    )
    if meta["status"] not in (204, 304):
        return False, f"stop -> HTTP {meta['status']}: {raw[:200].decode(errors='replace')}"
    return True, "stopped"


def _start_web_container(cid: str) -> tuple[bool, str]:
    meta, raw = _docker_raw_request(
        "POST", f"{_api_prefix()}/containers/{cid}/start",
        body=b"", content_type="application/json", timeout=30,
    )
    if meta["status"] not in (204, 304):
        return False, f"start -> HTTP {meta['status']}: {raw[:200].decode(errors='replace')}"
    return True, "started"


def prepare_clean_web_state() -> bool:
    """Cold-start the web service against an empty durable log so the
    one-shot acceptance is reproducible (first freezes really return 201).
    The previous log is archived, not deleted, for forensic inspection."""
    print("\n=== prepare: cold web start with a clean durable log ===", flush=True)
    if not os.path.exists(SOCK_PATH):
        record("clean web state", False, f"{SOCK_PATH} not available")
        return False
    cid = _find_web_container()
    if not cid:
        record("clean web state", False, "web container not found")
        return False
    data_dir = os.path.join(PROJECT_ROOT, "data")
    log_path = os.path.join(data_dir, "audit.log")

    ok, detail = _stop_web_container(cid)
    if not ok:
        record("clean web state: stop web", False, detail)
        return False
    try:
        os.makedirs(data_dir, exist_ok=True)
        if os.path.exists(log_path):
            archived = f"{log_path}.preverify.{int(time.time())}"
            os.replace(log_path, archived)
        for name in os.listdir(data_dir):
            if name.endswith(".tmp") or name.endswith(".verify-bak"):
                try:
                    os.unlink(os.path.join(data_dir, name))
                except OSError:
                    pass
    except OSError as exc:
        record("clean web state: archive old log", False, repr(exc))
        _start_web_container(cid)
        return False
    ok, detail = _start_web_container(cid)
    if not ok:
        record("clean web state: start web", False, detail)
        return False
    ok, detail = _wait_health("ok")
    record("clean web state", ok, f"cold start with empty log ({detail})")
    return ok


def _wait_health(expected: str = "ok", attempts: int = 20) -> tuple[bool, str]:
    for _ in range(attempts):
        try:
            status, _, body = http("GET", "/healthz")
        except (urllib.error.URLError, ConnectionError, json.JSONDecodeError):
            time.sleep(1)
            continue
        if expected == "ok" and status == 200:
            return True, "healthy"
        if expected == "unhealthy" and status == 503:
            return True, body.get("error", "503")
        time.sleep(1)
    return False, f"never reached expected health state {expected!r}"


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


def _durability_payloads(token: str) -> tuple[dict, dict, dict]:
    serial = {
        "audit_id": f"durability-serial-{token}",
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
    skew = {
        "audit_id": f"durability-skew-{token}",
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
    race = {
        "audit_id": f"durability-race-{token}",
        "initial": {"x": 0},
        "transactions": [
            {"id": "T1", "start": 1, "commit": 2, "steps": [
                {"op": "write", "key": "x", "value": 1}]}],
    }
    return serial, skew, race


def _concurrent_post(payload: dict) -> tuple[int, dict]:
    status, _, body = http("POST", "/api/audits", payload)
    return status, body


def run_restart_durability() -> bool:
    """Freeze records, restart the real web container, then prove on the
    fresh process that verdicts replay, conflicts hold, an unfinished tail
    is unreadable, and a corrupted committed record fails health."""
    print("\n=== 5/5 restart durability (Compose restart + crash tail) ===", flush=True)
    all_ok = True

    def expect(name, cond, detail=""):
        nonlocal all_ok
        record(name, cond, detail)
        all_ok = all_ok and cond

    if not os.path.exists(SOCK_PATH):
        expect("docker engine available for web restart", False,
               f"{SOCK_PATH} not available")
        return False
    cid = _find_web_container()
    if not cid:
        expect("locate web container", False, "no compose 'web' container found")
        return False
    expect("locate web container", True, cid[:12])

    log_path = os.path.join(PROJECT_ROOT, "data", "audit.log")
    token = f"{int(time.time())}-{os.getpid()}"
    serial, skew, race = _durability_payloads(token)
    lost_id = f"durability-lost-{token}"

    # -- phase 1: create frozen conclusions --------------------------------
    status, _, serial_body = http("POST", "/api/audits", serial)
    expect("durable: serializable verdict created",
           status == 201 and serial_body
           and serial_body.get("serial_order") == ["T1", "T2"],
           f"POST -> {status}")
    status, _, skew_body = http("POST", "/api/audits", skew)
    expect("durable: not-serializable verdict created",
           status == 201 and skew_body
           and skew_body.get("status") == "NOT_SERIALIZABLE",
           f"POST -> {status}")

    # concurrent identical submissions must collapse onto one freeze
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _: _concurrent_post(race), range(8)))
    created = [o for o in outcomes if o[0] == 201]
    replayed = [o for o in outcomes if o[0] == 200]
    expect("durable: concurrent identical submits freeze exactly once",
           len(created) == 1 and len(replayed) == 7
           and all(o[1] == created[0][1] for o in replayed + created),
           f"{len(created)} x 201, {len(replayed)} x 200")

    status, headers, _ = http("POST", "/api/audits", serial)
    expect("durable: pre-restart identical replay",
           status == 200 and headers.get("X-Audit-Replayed") == "true",
           f"POST -> {status}")
    with open(log_path, "rb") as f:
        on_disk = f.read()
    expect("durable: record fully on platter before success",
           os.path.exists(log_path) and serial["audit_id"].encode() in on_disk,
           log_path)

    # snapshot the intact log before any crash simulation
    backup = log_path + ".verify-bak"
    shutil.copy2(log_path, backup)

    # -- phase 2: restart the application container ------------------------
    ok, detail = _restart_web_container(cid)
    expect("restart web container", ok, detail)
    if not ok:
        return False
    ok, detail = _wait_health("ok")
    expect("healthy after restart with replayed index", ok, detail)

    status, _, fetched = http("GET", f"/api/audits/{serial['audit_id']}")
    expect("restart: original serializable conclusion replayed",
           status == 200 and fetched == serial_body,
           f"GET -> {status}")
    status, _, fetched_skew = http("GET", f"/api/audits/{skew['audit_id']}")
    expect("restart: original cycle evidence replayed",
           status == 200 and fetched_skew == skew_body,
           f"GET -> {status}")

    status, headers, replay = http("POST", "/api/audits", serial)
    expect("restart: same id + same payload replays",
           status == 200 and headers.get("X-Audit-Replayed") == "true"
           and replay == serial_body, f"POST -> {status}")

    changed = json.loads(json.dumps(serial))
    changed["initial"]["x"] = 999
    status, _, body = http("POST", "/api/audits", changed)
    expect("restart: changed payload still conflicts",
           status == 409 and body.get("error") == "AUDIT_ID_CONFLICT",
           f"POST changed -> {status}")

    # -- phase 3: unfinished tail after a crash must not become readable ---
    with open(log_path, "ab") as f:
        f.write(b'{"version":1,"audit_id":"' + lost_id.encode()
                + b'","fingerprint":"' + b"0" * 64 + b'"')  # no newline
    ok, _ = _restart_web_container(cid)
    expect("restart with unfinished tail", ok)
    ok, detail = _wait_health("ok")
    expect("tail: health stays ok (unfinished write dropped)", ok, detail)
    status, _, _ = http("GET", f"/api/audits/{lost_id}")
    expect("tail: unfinished write never becomes a readable conclusion",
           status == 404, f"GET -> {status}")
    status, _, still = http("GET", f"/api/audits/{serial['audit_id']}")
    expect("tail: committed conclusions remain readable",
           status == 200 and still == serial_body, f"GET -> {status}")

    # -- phase 4: damaged *committed* record must fail health --------------
    # Recovery skips an unterminated tail without rewriting the file, so
    # consider terminated lines only.
    with open(log_path, "rb") as f:
        raw = f.read()
    if raw.endswith(b"\n"):
        committed_lines = raw[:-1].split(b"\n")
    else:
        head, _, _ = raw.rpartition(b"\n")
        committed_lines = head.split(b"\n") if head else []
    idx = next(i for i, l in enumerate(committed_lines)
               if json.loads(l)["audit_id"] == serial["audit_id"])
    damaged = json.loads(committed_lines[idx])
    damaged["fingerprint"] = "f" * 64
    committed_lines[idx] = json.dumps(damaged, separators=(",", ":")).encode()
    with open(log_path, "wb") as f:
        f.write(b"\n".join(committed_lines) + b"\n")
    ok, _ = _restart_web_container(cid)
    expect("restart with corrupted committed record", ok)
    ok, detail = _wait_health("unhealthy")
    expect("corruption: health explicitly fails",
           ok and detail == "AUDIT_LOG_CORRUPT", f"health detail={detail!r}")
    status, _, bad = http("GET", f"/api/audits/{serial['audit_id']}")
    expect("corruption: no verdict served from unverifiable log",
           status == 503 and bad.get("error") == "AUDIT_LOG_CORRUPT",
           f"GET -> {status}")
    status, _, body = http("POST", "/api/audits", skew)
    expect("corruption: writes refused while log unverifiable",
           status == 503 and body.get("error") == "AUDIT_LOG_INTEGRITY",
           f"POST -> {status}")

    # -- restore the intact log and confirm the service recovers ----------
    shutil.copy2(backup, log_path)
    ok, _ = _restart_web_container(cid)
    expect("restart after restoring intact log", ok)
    ok, detail = _wait_health("ok")
    expect("service healthy again after log restored", ok, detail)
    try:
        os.unlink(backup)
    except OSError:
        pass
    return all_ok


def main() -> int:
    print(f"mvscc verify: target={SMOKE_TARGET} project={PROJECT_ROOT}", flush=True)
    ok_tests = run_code_tests()
    ok_fuzz = run_differential_fuzz()
    ok_image = run_image_build_check()
    ok_clean = prepare_clean_web_state()
    ok_smoke = run_http_smoke() if ok_clean else False
    ok_restart = run_restart_durability() if ok_clean else False

    print("\n=== acceptance summary ===")
    for name, ok, _ in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    code = 0 if (
        ok_tests and ok_fuzz and ok_image and ok_clean
        and ok_smoke and ok_restart
    ) else 1
    print(f"\nverify exit code: {code}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
