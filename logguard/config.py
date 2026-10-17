"""Configuration loaded from environment / .env file."""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parent.parent
load_dotenv(ROOT_DIR / ".env")


def _get(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip()


# Groq Cloud (OpenAI-compatible). Keys start with "gsk_".
GROQ_API_KEY = _get("GROQ_API_KEY")
GROQ_API_BASE = _get("GROQ_API_BASE", "https://api.groq.com/openai/v1")
GROQ_MODEL = _get("GROQ_MODEL", "openai/gpt-oss-120b")

# xAI Grok (OpenAI-compatible). Keys start with "xai-".
XAI_API_KEY = _get("XAI_API_KEY")
XAI_API_BASE = _get("XAI_API_BASE", "https://api.x.ai/v1")
XAI_MODEL = _get("XAI_MODEL", "grok-2-latest")

# Google Gemini.
GEMINI_API_KEY = _get("GEMINI_API_KEY")
GEMINI_MODEL = _get("GEMINI_MODEL", "gemini-flash-latest")
GEMINI_API_BASE = _get(
    "GEMINI_API_BASE", "https://generativelanguage.googleapis.com/v1beta"
)

GITHUB_TOKEN = _get("GITHUB_TOKEN")
LLM_PROVIDER = _get("LLM_PROVIDER", "groq").lower()

# Processing limits (Secure Processing Layer)
MAX_FILE_BYTES = 1_500_000        # per source file
MAX_TOTAL_BYTES = 25_000_000      # per scan
MAX_FILES = 500
MAX_FILE_LINES = 20_000

_PROVIDER_ORDER = ("groq", "gemini", "xai")


def _is_real_key(value: str) -> bool:
    return bool(value) and "your_" not in value.lower() and value.lower() != "changeme"


def available_providers() -> dict[str, bool]:
    """Return which LLM providers are configured with a usable key."""
    return {
        "groq": _is_real_key(GROQ_API_KEY),
        "gemini": _is_real_key(GEMINI_API_KEY),
        "xai": _is_real_key(XAI_API_KEY),
    }
