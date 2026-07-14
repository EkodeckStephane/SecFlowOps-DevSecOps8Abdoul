#!/usr/bin/env python3
"""Controlled vulnerable API for SecFlowOps experiments.

This app is intentionally simple and intentionally contains defensive test
findings. It must not be exposed to the public internet.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse
import sqlite3


def render_search_response(query: str) -> str:
    # Intentional SAST finding: reflected unescaped user input for scanner tests.
    body = f"<html><body>Search: {query}</body></html>"
    return body


def unsafe_user_lookup(username: str) -> list[tuple]:
    # Intentional SAST finding: string-formatted SQL query for scanner tests.
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (name TEXT)")
    conn.execute("INSERT INTO users VALUES ('alice')")
    query = f"SELECT name FROM users WHERE name = '{username}'"
    return list(conn.execute(query))


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._send(200, "ok")
            return

        if parsed.path == "/search":
            query = parse_qs(parsed.query).get("q", [""])[0]
            self._send(200, render_search_response(query), content_type="text/html")
            return

        if parsed.path == "/lookup":
            username = parse_qs(parsed.query).get("u", [""])[0]
            rows = unsafe_user_lookup(username)
            self._send(200, {"rows": rows})
            return

        self._send(404, "not found")

    def _send(self, status: int, payload, content_type: str = "text/plain") -> None:
        data = str(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main() -> None:
    server = HTTPServer(("127.0.0.1", 8080), Handler)
    print("sample_api listening on http://127.0.0.1:8080")
    server.serve_forever()


if __name__ == "__main__":
    main()
