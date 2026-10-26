"""Provider-neutral LLM layer. Everything is configured by environment variables (or .env); nothing is hard-coded.

  LLM_PROVIDER      anthropic (default) | openai   ("openai" = any OpenAI-compatible /chat/completions server:
                    OpenAI, Azure-style gateways, OpenRouter, LiteLLM, vLLM, Ollama, LM Studio, ...)
  LLM_BASE_URL      override the API root. anthropic: e.g. https://my-gateway/anthropic   openai: e.g. http://localhost:11434/v1
                    (ANTHROPIC_BASE_URL / OPENAI_BASE_URL are honoured as fallbacks)
  LLM_API_KEY       key for the chosen provider (fallbacks: ANTHROPIC_API_KEY / OPENAI_API_KEY). An openai-compatible server
                    with a custom base URL may run without a key.
  LLM_AUTH_TOKEN    anthropic only: bearer token instead of x-api-key (ANTHROPIC_AUTH_TOKEN also works)
  HUNT_MODEL        default model for every role (default for anthropic: claude-sonnet-5-5; REQUIRED for openai)
  LLM_MODEL_<ROLE>  per-role override, e.g. LLM_MODEL_SKEPTIC (roles: see ROLES)
  LLM_EXTRA_HEADERS JSON object of extra HTTP headers   LLM_TIMEOUT_S request timeout (default 120)
  LLM_TEMPERATURE   optional; sent only when set (some models reject sampling parameters)
  LLM_JSON_MODE=1   openai only: ask the server for a JSON object (response_format), if it supports it
  HUNT_FORCE_RULES=1 disables the LLM entirely (used by the tests)

If the chosen provider is not usable, get_llm() returns None and every agent falls back to its rule implementation.
Every call of a run goes to runs/<run_id>/llm.jsonl (start_trace) and counts against HUNT_LLM_MAX_CALLS.
"""
from __future__ import annotations
import asyncio, hashlib, json, os, re, time
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse
from . import config, progress  # config loads .env

ROLES = ("intake", "investigator", "skeptic", "responder", "classifier", "queue", "chat")
DEFAULT_MODELS = {"anthropic": "claude-sonnet-5-5"}


class LLMBudgetExceeded(RuntimeError):
    pass


@dataclass
class RunTrace:
    """Per-run LLM log and call budget. Kept in a ContextVar, so hunts running concurrently in one process stay apart."""
    path: Path | None
    max_calls: int
    temperature: float | None = None      # deterministic_sampling sets 0
    seq: int = 0
    tokens_in: int = 0
    tokens_out: int = 0


_TRACE: ContextVar[RunTrace | None] = ContextVar("llm_trace", default=None)
_OVERRIDE = None                           # tests install a scripted LLM here (tests/fake_llm.py)


def start_trace(path: Path | None, max_calls: int | None = None, temperature: float | None = None) -> RunTrace:
    t = RunTrace(path, max_calls or config.LLM_MAX_CALLS, temperature)
    if path:
        path.unlink(missing_ok=True)
    _TRACE.set(t)
    return t


def current_trace() -> RunTrace | None:
    return _TRACE.get()


def check_budget():
    t = _TRACE.get()
    if t and t.seq >= t.max_calls:
        raise LLMBudgetExceeded(f"LLM call budget ({t.max_calls}) exhausted")


def record(role: str | None, model: str, system: str, msgs: list[dict], text: str, tin, tout, ms: int):
    """Append one LLM call to the run's llm.jsonl: full messages and response, plus a prompt hash to compare runs."""
    progress.llm_call(role, model, tin, tout, ms)
    t = _TRACE.get()
    if not t:
        return
    t.seq += 1
    t.tokens_in += tin or 0
    t.tokens_out += tout or 0
    prompt = json.dumps({"system": system, "messages": msgs}, sort_keys=True)
    if t.path:
        with open(t.path, "a") as f:
            f.write(json.dumps({"seq": t.seq, "role": role, "model": model, "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
                                "system": system, "messages": msgs, "response": text, "tokens_in": tin, "tokens_out": tout,
                                "ms": ms}) + "\n")


def _env(*names: str) -> str:
    for n in names:
        if os.environ.get(n):
            return os.environ[n]
    return ""


@dataclass
class LLMSettings:
    provider: str = "anthropic"
    base_url: str = ""
    api_key: str = ""
    auth_token: str = ""
    model: str = ""
    role_models: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    timeout: float = 120.0
    temperature: float | None = None
    json_mode: bool = False

    @classmethod
    def from_env(cls) -> "LLMSettings":
        p = (_env("LLM_PROVIDER") or "anthropic").lower()
        if p not in ("anthropic", "openai"):
            raise ValueError(f"LLM_PROVIDER must be anthropic or openai, got {p!r}")
        s = cls(provider=p)
        if p == "anthropic":
            s.base_url = _env("LLM_BASE_URL", "ANTHROPIC_BASE_URL")
            s.api_key = _env("LLM_API_KEY", "ANTHROPIC_API_KEY")
            s.auth_token = _env("LLM_AUTH_TOKEN", "ANTHROPIC_AUTH_TOKEN")
        else:
            s.base_url = _env("LLM_BASE_URL", "OPENAI_BASE_URL") or "https://api.openai.com/v1"
            s.api_key = _env("LLM_API_KEY", "OPENAI_API_KEY")
        s.model = _env("HUNT_MODEL") or DEFAULT_MODELS.get(p, "")
        s.role_models = {r: _env(f"LLM_MODEL_{r.upper()}") for r in ROLES if _env(f"LLM_MODEL_{r.upper()}")}
        if _env("LLM_EXTRA_HEADERS"):
            s.headers = json.loads(_env("LLM_EXTRA_HEADERS"))
        if _env("LLM_TIMEOUT_S"):
            s.timeout = float(_env("LLM_TIMEOUT_S"))
        if _env("LLM_TEMPERATURE"):
            s.temperature = float(_env("LLM_TEMPERATURE"))
        s.json_mode = _env("LLM_JSON_MODE") == "1"
        return s

    def usable(self) -> bool:
        if not self.model:
            return False
        if self.provider == "anthropic":
            return bool(self.api_key or self.auth_token)
        local = bool(self.base_url) and "api.openai.com" not in self.base_url     # custom/local server: key optional
        return bool(self.api_key) or local

    def model_for(self, role: str | None) -> str:
        return self.role_models.get(role or "", "") or self.model


class LLM:
    def __init__(self, settings: LLMSettings | None = None, role: str | None = None, model: str | None = None):
        self.s = settings or LLMSettings.from_env()
        self.role = role
        self.model = model or self.s.model_for(role)
        self.calls: list[dict] = []
        self._client = None

    # ---- description (goes into run manifests; never includes secrets)
    def describe(self) -> str:
        host = urlparse(self.s.base_url).netloc if self.s.base_url else "default"
        return f"{self.s.provider}:{self.model}@{host}"

    # ---- anthropic client
    @property
    def client(self):
        if self.s.provider != "anthropic":
            raise RuntimeError("client is only available for provider=anthropic")
        if self._client is None:
            import anthropic
            kw: dict = {"timeout": self.s.timeout}
            if self.s.base_url: kw["base_url"] = self.s.base_url
            if self.s.api_key: kw["api_key"] = self.s.api_key
            if self.s.auth_token: kw["auth_token"] = self.s.auth_token
            if self.s.headers: kw["default_headers"] = self.s.headers
            self._client = anthropic.Anthropic(**kw)
        return self._client

    def _http(self):
        import httpx
        h = {"Content-Type": "application/json", **self.s.headers}
        if self.s.api_key:
            h["Authorization"] = f"Bearer {self.s.api_key}"
        return httpx.Client(base_url=self.s.base_url.rstrip("/"), headers=h, timeout=self.s.timeout, transport=getattr(self, "_transport", None))

    def _temperature(self) -> float | None:
        t = _TRACE.get()
        return t.temperature if t and t.temperature is not None else self.s.temperature

    def _openai_post(self, body: dict) -> dict:
        if self._temperature() is not None:
            body["temperature"] = self._temperature()
        if self.s.json_mode:
            body["response_format"] = {"type": "json_object"}
        with self._http() as c:
            r = c.post("/chat/completions", json=body)
        if r.status_code >= 400:
            raise RuntimeError(f"LLM HTTP {r.status_code}: {r.text[:300]}")
        return r.json()

    # ---- single JSON answer
    def _text(self, system: str, msgs: list[dict], max_tokens: int, model: str) -> str:
        check_budget()
        t0 = time.time()
        if self.s.provider == "anthropic":
            kw = {"temperature": self._temperature()} if self._temperature() is not None else {}
            r = self.client.messages.create(model=model, max_tokens=max_tokens, system=system, messages=msgs, **kw)
            self.calls.append({"model": model, "in": r.usage.input_tokens, "out": r.usage.output_tokens})
            text = "".join(b.text for b in r.content if b.type == "text")
            record(self.role, model, system, msgs, text, r.usage.input_tokens, r.usage.output_tokens, int((time.time() - t0) * 1000))
            return text
        mt = max_tokens
        for _ in range(3):
            j = self._openai_post({"model": model, "max_tokens": mt, "messages": [{"role": "system", "content": system}] + msgs})
            u = j.get("usage", {})
            self.calls.append({"model": model, "in": u.get("prompt_tokens"), "out": u.get("completion_tokens")})
            ch = j["choices"][0]
            text = ch["message"].get("content") or ""
            record(self.role, model, system, msgs, text, u.get("prompt_tokens"), u.get("completion_tokens"), int((time.time() - t0) * 1000))
            # reasoning models spend the budget on hidden thinking and can return empty content with finish_reason=length
            if text.strip() or ch.get("finish_reason") != "length" or mt >= 32000:
                return text
            mt = min(mt * 4, 32000)
            check_budget()
        return text

    def complete_json(self, system: str, user: str, max_tokens: int = 2000, model: str | None = None) -> dict:
        """Ask for a single JSON object; one repair retry on malformed output."""
        model = model or self.model
        msgs = [{"role": "user", "content": user}]
        for _ in range(2):
            text = self._text(system + "\nRespond with ONE JSON object only, no prose.", msgs, max_tokens, model)
            m = re.search(r"\{.*\}", text, re.S)
            try:
                return json.loads(m.group(0)) if m else json.loads(text)
            except Exception:
                msgs += [{"role": "assistant", "content": text}, {"role": "user", "content": "Invalid JSON. Return only valid JSON."}]
        raise ValueError("LLM did not return valid JSON")


def set_override(fake) -> None:
    """Tests only: get_llm() returns fake.bind(role) instead of a real client (None restores normal behaviour)."""
    global _OVERRIDE
    _OVERRIDE = fake


def get_llm(role: str | None = None, **kw) -> LLM | None:
    """Return a configured LLM or None (=> rule backend). `role` selects LLM_MODEL_<ROLE> if set."""
    if _OVERRIDE is not None:
        return _OVERRIDE.bind(role)
    if os.environ.get("HUNT_FORCE_RULES") == "1":
        return None
    try:
        s = LLMSettings.from_env()
    except Exception:
        return None
    return LLM(s, role=role, **kw) if s.usable() else None


async def ask_json(role: str, system: str, user: str, notes: list[str], max_tokens: int = 2000) -> dict | None:
    """One JSON answer from the role's LLM, or None when no LLM is configured or the call fails (the caller then uses rules).
    Failures are written to `notes`; the blocking HTTP call runs in a thread so MCP sessions stay responsive."""
    llm = get_llm(role)
    if llm is None:
        return None
    try:
        r = await asyncio.to_thread(llm.complete_json, system, user, max_tokens)
    except Exception as e:
        notes.append(f"LLM {role} call failed, rules used instead: {type(e).__name__}: {str(e)[:160]}")
        return None
    if not isinstance(r, dict):
        notes.append(f"LLM {role} returned {type(r).__name__}, not an object; rules used instead")
        return None
    return r


if __name__ == "__main__":   # python -m threat_hunting.llm   -> show effective configuration and make one test call
    s = LLMSettings.from_env()
    print(f"provider={s.provider} base_url={s.base_url or '(sdk default)'} default_model={s.model or '(none: set HUNT_MODEL)'} "
          f"role_models={s.role_models} key={'set' if s.api_key or s.auth_token else 'not set'} usable={s.usable()}")
    if s.usable():
        for role in (None, *ROLES):
            l = LLM(s, role=role)
            if role is None or role in s.role_models:
                try:
                    r = l.complete_json("Reply with {\"ok\": true}", "go", max_tokens=50)
                except Exception as e:
                    r = f"FAILED: {type(e).__name__}: {str(e)[:160]}"
                print(f"{role or 'default':10s} {l.describe():55s}", r)
