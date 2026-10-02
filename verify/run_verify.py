#!/usr/bin/env python3
"""One-shot acceptance service.

Runs, in order:

  1. code tests            -- unittest suite under /app/verify/tests
  2. image build check     -- builds the project image through the Docker
                              Engine API on /var/run/docker.sock (no docker
                              CLI / pip packages needed)
  3. HTTP smoke            -- exercises the real web service end to end

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
import time
import unittest
import urllib.error
import urllib.request

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
    print("\n=== 1/4 code tests ===", flush=True)
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
    print("\n=== 2/4 differential fuzz ===", flush=True)
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
    print("\n=== 3/4 image build check ===", flush=True)
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
    print("\n=== 4/4 HTTP smoke ===", flush=True)
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


def main() -> int:
    print(f"mvscc verify: target={SMOKE_TARGET} project={PROJECT_ROOT}", flush=True)
    ok_tests = run_code_tests()
    ok_fuzz = run_differential_fuzz()
    ok_image = run_image_build_check()
    ok_smoke = run_http_smoke()

    print("\n=== acceptance summary ===")
    for name, ok, _ in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    code = 0 if (ok_tests and ok_fuzz and ok_image and ok_smoke) else 1
    print(f"\nverify exit code: {code}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
