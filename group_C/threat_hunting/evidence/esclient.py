"""Read-only Elasticsearch client using only the standard library (elasticsearch-py is not needed).

The client sends four kinds of request: ``GET /``, ``GET /<index>/_doc/<id>``, ``POST /<index>/_count`` and
``POST /<index>/_search``. Any other method or path raises ``PermissionError``, and so does a request body that
contains a script. Give it a read-only API key anyway.
"""

from __future__ import annotations

import base64
import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence


class SourceUnavailable(RuntimeError):
    """The log store cannot be reached or answered unexpectedly."""


@dataclass(frozen=True)
class DocRef:
    index: str
    doc_id: str


@dataclass
class ReadOnlyES:
    url: str = "http://localhost:9200"
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    ca_cert: Optional[str] = None
    verify_tls: bool = True
    timeout: float = 10.0
    mode: str = field(default="elasticsearch", init=False)

    _ALLOWED = (
        ("GET", re.compile(r"^/?$")),
        ("GET", re.compile(r"^/[^/?_][^/?]*/_doc/[^/?]+$")),
        ("POST", re.compile(r"^/[^/?_][^/?]*/_count(\?[^/]*)?$")),
        ("POST", re.compile(r"^/[^/?_][^/?]*/_search(\?[^/]*)?$")),
    )
    FORBIDDEN_KEYS = {"script", "script_score", "runtime_mappings", "scripted_metric", "script_fields", "stored_fields"}

    @classmethod
    def from_env(cls) -> "ReadOnlyES":
        """Build a client from the ES_* environment variables."""
        return cls(
            url=os.getenv("ES_URL", "http://localhost:9200"),
            api_key=os.getenv("ES_API_KEY") or None,
            username=os.getenv("ES_USERNAME") or None,
            password=os.getenv("ES_PASSWORD") or None,
            ca_cert=os.getenv("ES_CA_CERT") or None,
            verify_tls=os.getenv("ES_VERIFY_TLS", "true").lower() not in ("0", "false", "no"),
            timeout=float(os.getenv("ES_TIMEOUT", "10")),
        )

    def _request(self, method: str, path: str, body: Optional[Mapping[str, Any]] = None) -> tuple[int, Any]:
        if not any(method == m and rx.match(path) for m, rx in self._ALLOWED):
            raise PermissionError(f"C3 source is read-only, so {method} {path} is refused")
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url.rstrip("/") + path, data=data, method=method)
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if self.api_key:
            req.add_header("Authorization", f"ApiKey {self.api_key}")
        elif self.username:
            token = base64.b64encode(f"{self.username}:{self.password or ''}".encode()).decode()
            req.add_header("Authorization", f"Basic {token}")
        ctx: Optional[ssl.SSLContext] = None
        if self.url.startswith("https"):
            ctx = ssl.create_default_context(cafile=self.ca_cert) if self.ca_cert else ssl.create_default_context()
            if not self.verify_tls:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                return resp.status, json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            try:
                return exc.code, json.loads(payload or b"null")
            except json.JSONDecodeError:
                return exc.code, {"error": payload.decode(errors="replace")}
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            raise SourceUnavailable(f"Elasticsearch unreachable at {self.url}: {exc}") from exc

    def available(self) -> bool:
        """True when the cluster answers ``GET /`` with 200."""
        try:
            status, _ = self._request("GET", "/")
            return status == 200
        except SourceUnavailable:
            return False

    def fetch_documents(self, refs: Sequence[DocRef]) -> dict[DocRef, Optional[dict[str, Any]]]:
        """Map each ref to its ``_source``, or to None when the document does not exist."""
        out: dict[DocRef, Optional[dict[str, Any]]] = {}
        for ref in refs:
            path = f"/{urllib.parse.quote(ref.index, safe='')}/_doc/{urllib.parse.quote(ref.doc_id, safe='')}"
            status, payload = self._request("GET", path)
            if status == 200 and isinstance(payload, Mapping) and payload.get("found"):
                out[ref] = dict(payload.get("_source") or {})
            elif status == 404 or (isinstance(payload, Mapping) and payload.get("found") is False):
                out[ref] = None
            else:
                raise SourceUnavailable(f"unexpected response {status} for {ref}: {payload}")
        return out

    def post(self, index: str, endpoint: str, body: dict[str, Any]) -> dict[str, Any]:
        """POST a recorded query body to /<index>/_search or /_count. Scripts are refused."""
        self._check_body(body)
        path = f"/{urllib.parse.quote(index, safe='*,-.')}/{endpoint}?ignore_unavailable=true&allow_no_indices=true"
        status, payload = self._request("POST", path, body)
        if status != 200:
            raise SourceUnavailable(f"{endpoint} on {index} returned {status}: {str(payload)[:200]}")
        return payload

    def _check_body(self, obj: Any) -> None:
        if isinstance(obj, dict):
            bad = self.FORBIDDEN_KEYS & set(obj)
            if bad:
                raise PermissionError(f"refusing DSL with {sorted(bad)}")
            for v in obj.values():
                self._check_body(v)
        elif isinstance(obj, list):
            for v in obj:
                self._check_body(v)
