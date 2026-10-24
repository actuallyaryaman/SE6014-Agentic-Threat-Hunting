"""OpenRouter-backed candidate provider for B2 Batch 3 agentic generation.

OpenRouter is reached through the OpenAI-compatible ``/chat/completions``
endpoint. The provider in this module is deliberately small so that:

* tests can inject a deterministic offline ``inference`` callable, so no
  network access is required to exercise the generation loop;
* production callers can wire a real OpenRouter API key through
  :meth:`OpenRouterCandidateProvider.from_env` at deployment time;
* the model's response is expected to be a JSON array of ``SchemaSpec``
  dictionaries, so downstream compilation and validation stay deterministic;
* nothing in this module performs i/o unless :meth:`propose` is called.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Protocol

from group_B.common.errors import SchemaGenerationError

try:  # optional dependency; onboarding CLI wires a real key in Batch 4
    import httpx
except ModuleNotFoundError:  # pragma: no cover - httpx is pinned but keep safe
    httpx = None


DEFAULT_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_OPENROUTER_MODEL = "google/gemini-2.0-flash-001"
DEFAULT_OPENROUTER_TEMPERATURE = 0.0
DEFAULT_OPENROUTER_TIMEOUT_SECONDS = 45.0
MAX_PROMPT_SAMPLE_LINES = 12
MAX_PROMPT_SAMPLE_CHARS = 12_000

_SYSTEM_PROMPT = (
    "You propose candidate Elasticsearch ingest-pipeline schema candidates "
    "for the B2 unknown-schema generator. Reply with ONLY a JSON array. Every "
    "element must follow the B2 `SchemaSpec` shape: {schema_id, version, "
    "dataset, description, parser, timestamp, fields}. Reply with a maximum "
    "of 3 candidates, most likely first. Do not explain, do not wrap the "
    "JSON in prose or code fences."
)


class LlmInference(Protocol):
    """Injected offline inference callable used for deterministic tests."""

    def __call__(self, system: str, user: str) -> str:
        """Return the raw assistant text produced by the LLM."""


class OpenRouterCandidateProvider:
    """Candidate ``SchemaSpec`` proposers backed by the OpenRouter API."""

    def __init__(
        self,
        model: str | None = None,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        temperature: float = DEFAULT_OPENROUTER_TEMPERATURE,
        seed: int | None = None,
        timeout_seconds: float = DEFAULT_OPENROUTER_TIMEOUT_SECONDS,
        app_title: str | None = None,
        inference: LlmInference | None = None,
    ) -> None:
        self.model = model or DEFAULT_OPENROUTER_MODEL
        self.api_key = api_key
        self.base_url = base_url or DEFAULT_OPENROUTER_BASE_URL
        self.temperature = temperature
        self.timeout_seconds = timeout_seconds
        self.app_title = app_title or "se6014-groupb-b2"
        self.seed = seed
        self.system_prompt = _SYSTEM_PROMPT
        self.inference = inference

    @property
    def model_name(self) -> str:
        """Deterministic model identifier recorded in provenance."""

        return self.model

    @classmethod
    def from_env(
        cls,
        *,
        model_env: str = "OPENROUTER_MODEL",
        api_key_env: str = "OPENROUTER_API_KEY",
        base_url_env: str = "OPENROUTER_BASE_URL",
    ) -> "OpenRouterCandidateProvider":
        """Build a provider from environment variables for deployment."""

        model = os.environ.get(model_env)
        api_key = os.environ.get(api_key_env)
        if not api_key:
            raise SchemaGenerationError(
                f"missing environment variable {api_key_env}"
            )
        return cls(
            model=model,
            api_key=api_key,
            base_url=os.environ.get(base_url_env),
        )

    def propose(
        self,
        *,
        samples: Sequence[str],
        dataset_hint: str | None,
        signature: Any,
    ) -> Sequence[Mapping[str, Any]]:
        user_prompt = self._build_user_prompt(samples, dataset_hint)
        try:
            if self.inference is not None:
                response = self.inference(self.system_prompt, user_prompt)
            else:
                response = self._post_chat(user_prompt)
        except Exception as error:  # noqa: BLE001 - provider is untrusted
            raise SchemaGenerationError(
                f"OpenRouter inference failed: {error}"
            ) from error
        if not isinstance(response, str):
            raise SchemaGenerationError(
                "OpenRouter inference must return a string"
            )
        return self._parse_candidates(response)

    def _build_user_prompt(
        self,
        samples: Sequence[str],
        dataset_hint: str | None,
    ) -> str:
        trimmed: list[str] = []
        total = 0
        for line in samples:
            if not line or not line.strip():
                continue
            if total + len(line) > MAX_PROMPT_SAMPLE_CHARS:
                break
            if len(trimmed) >= MAX_PROMPT_SAMPLE_LINES:
                break
            trimmed.append(line)
            total += len(line)
        if not trimmed:
            return (
                "Samples:\n(no usable sample lines)\n\n"
                "Dataset hint:\n"
                f"{dataset_hint or 'unknown.dataset'}"
            )
        payload = {
            "dataset_hint": dataset_hint,
            "samples": trimmed,
        }
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    def _post_chat(self, user_prompt: str) -> str:
        if httpx is None:  # pragma: no cover - red warning, not a runtime path
            raise SchemaGenerationError(
                "httpx is required to call the OpenRouter API"
            )
        if not self.api_key:
            raise SchemaGenerationError(
                "OpenRouterCandidateProvider requires an API key"
            )
        response = httpx.post(
            f"{self.base_url.rstrip('/')}/chat/completions",
            headers=self._request_headers(),
            json={
                "model": self.model,
                "temperature": self.temperature,
                "seed": self.seed,
                "messages": [
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            },
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        body = response.json()
        try:
            return body["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as error:
            raise SchemaGenerationError(
                f"unexpected OpenRouter response: {error}"
            ) from error

    def _request_headers(self) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "X-Title": self.app_title,
        }
        return headers

    def _parse_candidates(self, text: str) -> list[Mapping[str, Any]]:
        array = _extract_json_array(text)
        if array is None:
            return []
        if not isinstance(array, list):
            return []
        candidates: list[Mapping[str, Any]] = []
        for item in array:
            if isinstance(item, Mapping):
                candidates.append(dict(item))
        return candidates


_JSON_ARRAY_RE = re.compile(r"\[.*\]", re.DOTALL)


def _extract_json_array(text: str) -> Any | None:
    """Best-effort, bounded JSON array extraction from an LLM reply."""

    if not isinstance(text, str):
        return None
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped)
        stripped = re.sub(r"\s*```$", "", stripped).strip()
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass
    match = _JSON_ARRAY_RE.search(stripped)
    if match is None:
        return None
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
