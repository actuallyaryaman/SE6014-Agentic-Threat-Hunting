"""Every tool call is recorded with the exact query, hit count and a hash of the result IDs."""
from __future__ import annotations
import hashlib, json, os, threading, time
from threat_hunting import config

_lock = threading.Lock()


class Audit:
    def __init__(self, run_id: str | None = None):
        self.run_id = run_id or os.environ.get("HUNT_RUN_ID", "adhoc")
        self.path = config.AUDIT_DIR / f"{self.run_id}.jsonl"
        config.AUDIT_DIR.mkdir(exist_ok=True)
        self.seq = sum(1 for _ in open(self.path)) if self.path.exists() else 0

    def record(self, tool: str, params: dict, dsl: dict | None, ids: list[str], total: int | None, ok: bool = True, error: str = "", digest: str = "") -> str:
        with _lock:
            self.seq += 1
            call_id = f"{self.run_id}-{self.seq:04d}"
            rec = {"call_id": call_id, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "tool": tool, "params": params,
                   "dsl": dsl, "total": total, "returned_ids": ids[:500],
                   "result_hash": hashlib.sha256(json.dumps([sorted(ids), total]).encode()).hexdigest()[:16], "ok": ok, "error": error, "digest": digest[:20000]}
            with open(self.path, "a") as f:
                f.write(json.dumps(rec, default=str) + "\n")
            return call_id

    @staticmethod
    def read(run_id: str) -> list[dict]:
        p = config.AUDIT_DIR / f"{run_id}.jsonl"
        return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []
