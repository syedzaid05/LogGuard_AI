"""AI Recommendation Module: LLM-backed explanations and fixes.

Supports Groq Cloud and xAI Grok (both OpenAI-compatible) plus Google Gemini
via plain REST calls, so no heavy vendor SDK is required.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

import requests

from . import config
from .models import Finding

SYSTEM_PROMPT = (
    "You are a senior application-security and Python reliability reviewer. "
    "Given static-analysis findings, explain the real-world impact concisely "
    "and provide a concrete, minimal fix. Be specific and avoid generic advice."
)

_AI_UNAVAILABLE = "AI recommendations unavailable (no API key configured or request failed)."


@dataclass
class AIMessage:
    ok: bool
    text: str
    provider: str = ""
    error: str = ""


def providers_status() -> dict[str, bool]:
    return config.available_providers()


def default_provider() -> str:
    status = config.available_providers()
    preferred = config.LLM_PROVIDER
    if status.get(preferred):
        return preferred
    for name, ok in status.items():
        if ok:
            return name
    return ""


def chat(prompt: str, provider: str | None = None, system: str = SYSTEM_PROMPT) -> AIMessage:
    provider = provider or default_provider()
    if not provider:
        return AIMessage(False, "", "", _AI_UNAVAILABLE)
    try:
        if provider == "groq":
            return _openai_chat(prompt, system, "groq", config.GROQ_API_KEY,
                                config.GROQ_API_BASE, config.GROQ_MODEL)
        if provider == "xai":
            return _openai_chat(prompt, system, "xai", config.XAI_API_KEY,
                                config.XAI_API_BASE, config.XAI_MODEL)
        if provider == "gemini":
            return _gemini_chat(prompt, system)
        return AIMessage(False, "", provider, f"Unknown provider: {provider}")
    except requests.RequestException as exc:
        return AIMessage(False, "", provider, f"Network error: {exc}")
    except Exception as exc:  # noqa: BLE001
        return AIMessage(False, "", provider, f"{type(exc).__name__}: {exc}")


def enrich_findings(findings: list[Finding], provider: str | None = None, limit: int = 20) -> AIMessage:
    """Attach AI explanations/fixes to the top findings in place."""
    target = findings[:limit]
    if not target:
        return AIMessage(False, "", "", "No findings to analyse.")

    lines = [
        "Analyse the following Python static-analysis findings.",
        "For each item respond as JSON with keys: index, impact, fix.",
        "Keep 'impact' and 'fix' to 1-2 sentences each.",
        "",
    ]
    for i, f in enumerate(target):
        lines.append(
            f"[{i}] rule={f.rule_id} sev={f.severity} file={f.file}:{f.line}\n"
            f"    title: {f.title}\n"
            f"    code: {f.code[:200]}"
        )

    message = chat("\n".join(lines), provider=provider)
    if not message.ok:
        return message

    mapping = _parse_items(message.text)
    for i, f in enumerate(target):
        item = mapping.get(i)
        if item:
            f.ai_explanation = str(item.get("impact", "")).strip()
            f.ai_fix = str(item.get("fix", "")).strip()
    return message


# ------------------------------------------------- OpenAI-compatible (Groq / xAI)
def _openai_chat(prompt: str, system: str, provider: str, key: str, base: str, model: str) -> AIMessage:
    url = f"{base.rstrip('/')}/chat/completions"
    resp = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        },
        timeout=60,
    )
    if resp.status_code >= 400:
        return AIMessage(False, "", provider, _http_error(resp))
    data = resp.json()
    text = data["choices"][0]["message"]["content"]
    return AIMessage(True, text, provider)


# -------------------------------------------------------------- Gemini REST
def _gemini_chat(prompt: str, system: str) -> AIMessage:
    url = (
        f"{config.GEMINI_API_BASE.rstrip('/')}/models/"
        f"{config.GEMINI_MODEL}:generateContent"
    )
    resp = requests.post(
        url,
        params={"key": config.GEMINI_API_KEY},
        json={
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2},
        },
        timeout=60,
    )
    if resp.status_code >= 400:
        return AIMessage(False, "", "gemini", _http_error(resp))
    data = resp.json()
    try:
        parts = data["candidates"][0]["content"]["parts"]
        text = "".join(p.get("text", "") for p in parts)
    except (KeyError, IndexError):
        return AIMessage(False, "", "gemini", "Unexpected response shape from Gemini.")
    return AIMessage(True, text, "gemini")


def _http_error(resp: requests.Response) -> str:
    try:
        detail = resp.json()
    except ValueError:
        detail = resp.text[:300]
    return f"HTTP {resp.status_code}: {detail}"


def _parse_items(text: str) -> dict[int, dict]:
    """Extract the JSON array from an LLM reply, tolerating markdown fences."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("```", 2)[1]
        if cleaned.startswith("json"):
            cleaned = cleaned[4:]
    start, end = cleaned.find("["), cleaned.rfind("]")
    if start == -1 or end == -1:
        return {}
    try:
        items = json.loads(cleaned[start : end + 1])
    except json.JSONDecodeError:
        return {}
    mapping: dict[int, dict] = {}
    for item in items:
        if isinstance(item, dict) and "index" in item:
            try:
                mapping[int(item["index"])] = item
            except (TypeError, ValueError):
                continue
    return mapping
