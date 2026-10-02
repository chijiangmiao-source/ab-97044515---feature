"""Tests for verify helper logic that can be checked without a daemon."""

import importlib.util
import json
import os
import socketserver
import tempfile
import threading
import unittest

spec = importlib.util.spec_from_file_location(
    "run_verify", os.path.join(os.path.dirname(__file__), "..", "run_verify.py")
)
run_verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run_verify)


class DechunkTests(unittest.TestCase):
    def test_simple_chunks(self):
        message = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
        self.assertEqual(run_verify._dechunk(message), b"hello world")

    def test_single_chunk(self):
        self.assertEqual(run_verify._dechunk(b"3\r\nabc\r\n0\r\n\r\n"), b"abc")

    def test_chunk_extensions_ignored(self):
        self.assertEqual(run_verify._dechunk(b"3;name=x\r\nabc\r\n0\r\n\r\n"), b"abc")

    def test_empty(self):
        self.assertEqual(run_verify._dechunk(b"0\r\n\r\n"), b"")


def chunked(events):
    body = "".join(json.dumps(e) + "\n" for e in events).encode()

    def chunk(data):
        return ("%x\r\n" % len(data)).encode() + data + b"\r\n"

    return chunk(body[: len(body) // 2 or 1]) + chunk(body[len(body) // 2 or 1:]) + b"0\r\n\r\n"


class FakeDocker(socketserver.UnixStreamServer):
    daemon = None
    allow_body_skip = True


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        request_line = self.rfile.readline().decode()
        length = 0
        while True:
            line = self.rfile.readline()
            if line in (b"\r\n", b"", b"\n"):
                break
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":", 1)[1])
        if length:
            self.rfile.read(length)  # build context tar, contents not inspected

        method, target, _ = request_line.split(" ", 2)
        if target.endswith("/version"):
            payload = json.dumps({"ApiVersion": "1.43"}).encode()
            self.wfile.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
                % (len(payload), payload)
            )
            return
        mode = self.server.mode
        if mode == "ok":
            events = [
                {"stream": "Step 1/3 : FROM python:3.11-slim\n"},
                {"stream": "Step 2/3 : COPY . .\n"},
                {"stream": "Successfully tagged test:latest\n"},
                {"aux": {"ID": "sha256:abc"}},
            ]
            self.wfile.write(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
            self.wfile.write(chunked(events))
        elif mode == "stream-error":
            events = [{"stream": "Step 1/3 : FROM nope\n"},
                      {"errorDetail": {"message": "manifest unknown"}, "error": "manifest unknown"}]
            self.wfile.write(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
            self.wfile.write(chunked(events))
        else:  # http-error
            payload = json.dumps({"message": "something broke"}).encode()
            self.wfile.write(
                b"HTTP/1.1 500 SERVER ERROR\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
                % (len(payload), payload)
            )


class ImageBuildCheckTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        with open(os.path.join(self.tmpdir, "Dockerfile"), "w") as f:
            f.write("FROM scratch\n")
        self.sock_path = os.path.join(self.tmpdir, "docker.sock")
        self.server = FakeDocker(self.sock_path, _Handler)
        self.server.mode = "ok"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self._old_sock = run_verify.SOCK_PATH
        run_verify.SOCK_PATH = self.sock_path

    def tearDown(self):
        run_verify.SOCK_PATH = self._old_sock
        self.server.shutdown()
        self.server.server_close()

    def test_successful_build(self):
        ok, detail = run_verify._docker_api_build(self.tmpdir, "test:latest")
        self.assertTrue(ok, detail)
        self.assertIn("test:latest", detail)

    def test_stream_error_is_failure(self):
        self.server.mode = "stream-error"
        ok, detail = run_verify._docker_api_build(self.tmpdir, "test:latest")
        self.assertFalse(ok)
        self.assertIn("manifest unknown", detail)

    def test_http_error_is_failure(self):
        self.server.mode = "http-error"
        ok, detail = run_verify._docker_api_build(self.tmpdir, "test:latest")
        self.assertFalse(ok)
        self.assertIn("500", detail)


if __name__ == "__main__":
    unittest.main(verbosity=2)
