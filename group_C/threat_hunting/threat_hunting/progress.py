"""Live progress on stderr: each phase with its duration, every MCP call (step, tool, hits, time), every LLM call (role, time,
tokens), each investigator turn and skeptic test, and a table of phase timings at the end (also kept in the run manifest).

On for `python -m threat_hunting.run` and `hunt_queue run` (off with --quiet), or with HUNT_PROGRESS=1; off in tests and in the
hunt MCP server, whose stdout carries the MCP protocol. It prints step ids, tools, counts, durations and the agent's own short
notes, never raw log values. State lives in a ContextVar, so concurrent hunts in one process do not mix their output."""
from __future__ import annotations
import os, sys, time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field


@dataclass
class Tracker:
    on: bool
    t0: float = field(default_factory=time.time)
    phases: list = field(default_factory=list)       # (name, seconds, mcp calls, llm calls)
    mcp: int = 0
    llm: int = 0


_P: ContextVar[Tracker | None] = ContextVar("progress", default=None)
_STEP: ContextVar[tuple[str, str] | None] = ContextVar("progress_step", default=None)


def start(on: bool | None = None) -> Tracker:
    """A new tracker for this run; on=None means the HUNT_PROGRESS environment variable decides."""
    t = Tracker(os.environ.get("HUNT_PROGRESS") == "1" if on is None else on)
    _P.set(t)
    return t


def secs(s: float) -> str:
    return f"{s * 1000:.0f} ms" if s < 1 else f"{s:.1f} s"


def log(msg: str):
    t = _P.get()
    if t and t.on:
        print(f"[{time.time() - t.t0:7.1f}s] {msg}", file=sys.stderr, flush=True)


@contextmanager
def phase(name: str, detail: str = ""):
    t = _P.get()
    if t is None:
        yield
        return
    m0, l0, s0 = t.mcp, t.llm, time.time()
    log(f"▶ {name}" + (f": {detail}" if detail else ""))
    try:
        yield
    finally:
        dt = time.time() - s0
        t.phases.append((name, dt, t.mcp - m0, t.llm - l0))
        log(f"✔ {name} done in {secs(dt)} ({t.mcp - m0} MCP call(s), {t.llm - l0} LLM call(s))")


@contextmanager
def step(label: str, note: str = ""):
    """Names the MCP calls made inside it (a plan step id, or a planning purpose such as 'coverage auth')."""
    tok = _STEP.set((label, note))
    try:
        yield
    finally:
        _STEP.reset(tok)


def _what(tool: str, a: dict) -> str:
    if tool in ("search", "count", "aggregate"):
        parts = [a.get("agg", ""), a.get("field", "")] if tool == "aggregate" else []
        ds = [f["value"] for f in a.get("filters") or [] if isinstance(f, dict) and f.get("field") == "event.dataset"]
        if ds:
            parts.append(f"dataset={ds[0] if not isinstance(ds[0], list) or len(ds[0]) > 1 else ds[0][0]}")
        n = len(a.get("filters") or []) + len(a.get("any_of") or []) + len(a.get("must_not") or [])
        parts.append(f"{n} filter(s)")
        return " ".join(str(p) for p in parts if p)
    if tool == "gap_check":
        return f"{len(a.get('buckets') or [])} bucket(s)"
    return " ".join(f"{k}={v}" for k, v in a.items() if isinstance(v, (str, int)))[:60]


def mcp_call(seq: int, server: str, tool: str, args: dict, out: dict, dt: float):
    t = _P.get()
    if t is None:
        return
    t.mcp += 1
    label, note = _STEP.get() or ("", "")
    if "error" in out:
        res = f"ERROR {str(out['error'])[:90]}"
    elif tool == "gap_check":
        res = f"coverage {out.get('coverage_ratio', 0):.0%}"
    elif isinstance(out.get("result"), list):
        res = f"{out.get('total', 0)} hit(s), {len(out['result'])} bucket(s)"
    else:
        res = f"{out.get('total', '-')} hit(s)"
    log(f"   #{seq:<3} {server}.{tool:<13} {('[' + label + '] ') if label else ''}{_what(tool, args)} → {res}  ({secs(dt)})"
        + (f"  {note[:70]}" if note else ""))


def llm_call(role, model: str, tin, tout, ms: int):
    t = _P.get()
    if t is None:
        return
    t.llm += 1
    log(f"   llm {str(role):<12} {model}  {secs(ms / 1000)}  tokens in/out {tin}/{tout}")


def summary() -> dict[str, float]:
    """Prints the phase table (when on) and returns {phase: seconds} for the run manifest."""
    t = _P.get()
    if t is None:
        return {}
    total = time.time() - t.t0
    if t.on:
        lines = ["", "Phase timings:", f"  {'phase':<22}{'time':>10}{'MCP':>6}{'LLM':>6}"]
        lines += [f"  {n:<22}{secs(s):>10}{m:>6}{l:>6}" for n, s, m, l in t.phases]
        lines.append(f"  {'total':<22}{secs(total):>10}{t.mcp:>6}{t.llm:>6}")
        print("\n".join(lines), file=sys.stderr, flush=True)
    out: dict[str, float] = {}
    for n, s, _, _ in t.phases:
        out[n] = round(out.get(n, 0) + s, 2)
    out["total"] = round(total, 2)
    return out
