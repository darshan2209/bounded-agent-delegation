"""A very small JSON-over-HTTP layer built on the standard library.

The laboratory deliberately avoids a web framework so that the artefact runs on
a bare Python 3.11 install with only PyJWT, cryptography and PyYAML present.
The service logic itself lives in `lab/services.py` and is identical whether the
experiment runs in-process or over HTTP.
"""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

Handler = Callable[[dict, dict], tuple[int, dict]]
"""A route handler takes (json_body, query) and returns (status, json_response)."""


def make_server(port: int, routes: dict[tuple[str, str], Handler],
                name: str = "service") -> ThreadingHTTPServer:
    class _Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # keep the test output readable
            pass

        def _respond(self, status: int, payload: dict) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _dispatch(self, method: str) -> None:
            path = self.path.split("?", 1)[0]
            handler = routes.get((method, path))
            if handler is None:
                self._respond(404, {"error": "not_found", "path": path})
                return
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            try:
                body = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                self._respond(400, {"error": "invalid_json"})
                return
            try:
                status, payload = handler(body, {})
            except Exception as exc:  # a service fault must not kill the server
                self._respond(500, {"error": "internal", "detail": str(exc)})
                return
            self._respond(status, payload)

        def do_GET(self):     # noqa: N802
            self._dispatch("GET")

        def do_POST(self):    # noqa: N802
            self._dispatch("POST")

        def do_DELETE(self):  # noqa: N802
            self._dispatch("DELETE")

    server = ThreadingHTTPServer(("0.0.0.0", port), _Handler)
    server.daemon_threads = True
    return server


def serve_forever(server: ThreadingHTTPServer, name: str) -> None:
    print(f"[{name}] listening on port {server.server_address[1]}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


def start_in_thread(server: ThreadingHTTPServer) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


def post(url: str, payload: dict, timeout: float = 5.0) -> tuple[int, dict]:
    data = json.dumps(payload).encode()
    request = urllib.request.Request(url, data=data, method="POST",
                                     headers={"Content-Type": "application/json"})
    return _send(request, timeout)


def get(url: str, timeout: float = 5.0) -> tuple[int, dict]:
    return _send(urllib.request.Request(url, method="GET"), timeout)


def _send(request: urllib.request.Request, timeout: float) -> tuple[int, dict]:
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read() or b"{}")
        except json.JSONDecodeError:
            return exc.code, {"error": "unreadable_body"}
