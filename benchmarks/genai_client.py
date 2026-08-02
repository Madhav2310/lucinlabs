"""Reusable OpenAI-compatible client (login -> JWT -> Bearer).

For gateways that issue a short-lived bearer token from a login call rather than
taking a static API key. Configure with environment variables:

  LUCIN_LLM_BASE_URL   base URL of the OpenAI-compatible endpoint
  LUCIN_LLM_LOGIN_URL  login endpoint that returns a JWT (optional)
  LUCIN_LLM_API_KEY    static key, if the gateway takes one
  LUCIN_LLM_CA_BUNDLE  path to a CA bundle, if behind a TLS-intercepting proxy
  LUCIN_LLM_MODEL      model identifier

Config is read at runtime; no paths are hardcoded. Used by guard_live_llm and
prove_real_asr for real-LLM validation. Frugal by design: callers pass small
max_completion_tokens and cap their own call counts.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

import httpx

ENV_PROPERTIES = os.environ.get("LUCIN_LLM_ENV_FILE", "")   # optional: a properties file with the same keys


def _load_cfg() -> dict:
    cfg = {}
    p = Path(ENV_PROPERTIES)
    if p.exists():
        for line in p.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()
    for k in ("GENAI_BASE_URL", "GENAI_AUTH_ID", "GENAI_AUTH_CREDENTIAL",
              "LUCIN_LLM_CA_BUNDLE", "LUCIN_LLM_MODEL"):
        if os.environ.get(k):
            cfg[k] = os.environ[k]
    return cfg


class GenAIClient:
    def __init__(self):
        self.cfg = _load_cfg()
        self.base = self.cfg.get("GENAI_BASE_URL", "").rstrip("/")
        self.model = self.cfg.get("LUCIN_LLM_MODEL", "gpt-5.4-mini")
        verify = self.cfg.get("LUCIN_LLM_CA_BUNDLE") or True
        self._client = httpx.Client(verify=verify, timeout=60)
        self._lock = threading.Lock()
        self._token: str | None = None
        self.calls = 0
        self.in_tokens = 0
        self.out_tokens = 0

    @property
    def configured(self) -> bool:
        return bool(self.base and self.cfg.get("GENAI_AUTH_CREDENTIAL"))

    def token(self) -> str:
        with self._lock:
            if self._token:
                return self._token
        r = self._client.post(f"{self.base}/genai-api/v1/auth/login",
                              json={"username": self.cfg.get("GENAI_AUTH_ID"),
                                    "password": self.cfg.get("GENAI_AUTH_CREDENTIAL")},
                              headers={"Content-Type": "application/json",
                                       "Accept": "application/json"})
        r.raise_for_status()
        tok = r.json()["access_token"]
        with self._lock:
            self._token = tok
        return tok

    def chat(self, messages: list, tools: list | None = None,
             max_completion_tokens: int = 512, tool_choice: str = "auto") -> dict:
        payload = {"model": self.model, "max_completion_tokens": max_completion_tokens,
                   "messages": messages}
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = tool_choice
        r = self._client.post(f"{self.base}/v1/chat/completions",
                              headers={"Authorization": f"Bearer {self.token()}",
                                       "Content-Type": "application/json"},
                              json=payload)
        r.raise_for_status()
        data = r.json()
        u = data.get("usage", {})
        with self._lock:
            self.calls += 1
            self.in_tokens += u.get("prompt_tokens", 0)
            self.out_tokens += u.get("completion_tokens", 0)
        return data

    def text(self, messages: list, max_completion_tokens: int = 256) -> str:
        return self.chat(messages, max_completion_tokens=max_completion_tokens
                         )["choices"][0]["message"].get("content") or ""
