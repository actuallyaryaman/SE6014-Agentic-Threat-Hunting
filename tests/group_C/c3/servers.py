"""Mock Elasticsearch over HTTP (backed by MiniES) for the gateway tests."""

from __future__ import annotations

import json
import re
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional

from .mini_es import MiniES


class MockES:
    def __init__(self, es: Optional[MiniES] = None) -> None:
        self.es = es or MiniES()
        self.requests: list[tuple[str, str]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code: int, payload: Any) -> None:
                body = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                outer.requests.append(("GET", self.path))
                path = urllib.parse.urlparse(self.path).path
                if path in ("", "/"):
                    return self._send(200, {"version": {"number": "8.17.0"}})
                m = re.match(r"^/([^/]+)/_doc/([^/]+)$", path)
                if m:
                    idx, did = (urllib.parse.unquote(x) for x in m.groups())
                    doc = outer.es.get(idx, did)
                    if doc is None:
                        return self._send(404, {"found": False})
                    return self._send(200, {"_index": idx, "_id": did, "found": True, "_source": doc})
                return self._send(400, {"error": "unsupported"})

            def do_POST(self):
                outer.requests.append(("POST", self.path))
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
                path = urllib.parse.urlparse(self.path).path
                m = re.match(r"^/([^/]+)/(_search|_count)$", path)
                if not m:
                    return self._send(400, {"error": "unsupported"})
                idx = urllib.parse.unquote(m.group(1))
                return self._send(200, outer.es.search(idx, body) if m.group(2) == "_search" else outer.es.count(idx, body))

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "MockES":
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.server.shutdown()
        self.server.server_close()
