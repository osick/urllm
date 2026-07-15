"""Shared fixtures: a configurable local HTTP server to exercise real fetches."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


@pytest.fixture()
def http_site():
    """Yield a `serve(html, headers, status)` function returning the site URL.

    Each call reconfigures what the local server responds with, so a test can
    exercise fetch_and_parse() against real HTTP traffic (cookies, CSP, …).
    """
    config = {"html": "<html><body>ok</body></html>", "headers": [], "status": 200}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 (http.server API)
            body = config["html"].encode("utf-8")
            self.send_response(config["status"])
            self.send_header("Content-Type", "text/html; charset=utf-8")
            for name, value in config["headers"]:
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # silence request logging
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def serve(html: str | None = None, headers=None, status: int = 200) -> str:
        if html is not None:
            config["html"] = html
        config["headers"] = headers or []
        config["status"] = status
        return f"http://127.0.0.1:{server.server_address[1]}/"

    yield serve
    server.shutdown()
