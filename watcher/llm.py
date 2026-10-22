"""Small provider-agnostic LLM client. Uses whichever key is set in .env:
ANTHROPIC_API_KEY, OPENAI_API_KEY or GEMINI_API_KEY. LLM_MODEL overrides the model.
With no key, available() is False and the agent runs on its rule-based brain."""
import json
import os
import re

import requests

DEFAULTS = {
    "anthropic": "claude-sonnet-5-5",
    "openai": "gpt-4.1-mini",
    "gemini": "gemini-2.5-flash",
}


def provider():
    if os.getenv("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.getenv("OPENAI_API_KEY"):
        return "openai"
    if os.getenv("GEMINI_API_KEY"):
        return "gemini"
    return None


def available():
    return provider() is not None


def model_name():
    p = provider()
    return os.getenv("LLM_MODEL") or DEFAULTS.get(p, "none")


def _extract_json(text):
    text = text.strip()
    m = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if m:
        text = m.group(1)
    start, end = text.find("{"), text.rfind("}")
    return json.loads(text[start:end + 1])


def chat_json(system, user, max_tokens=1500):
    """Send one prompt and return the reply parsed as a JSON object."""
    p, model = provider(), model_name()
    if p == "anthropic":
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": os.environ["ANTHROPIC_API_KEY"],
                     "anthropic-version": "2023-06-01", "content-type": "application/json"},
            json={"model": model, "max_tokens": max_tokens, "system": system,
                  "messages": [{"role": "user", "content": user}]},
            timeout=90)
        r.raise_for_status()
        text = "".join(b.get("text", "") for b in r.json()["content"])
    elif p == "openai":
        r = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": "Bearer " + os.environ["OPENAI_API_KEY"]},
            json={"model": model, "max_tokens": max_tokens,
                  "response_format": {"type": "json_object"},
                  "messages": [{"role": "system", "content": system},
                               {"role": "user", "content": user}]},
            timeout=90)
        r.raise_for_status()
        text = r.json()["choices"][0]["message"]["content"]
    elif p == "gemini":
        r = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
            headers={"x-goog-api-key": os.environ["GEMINI_API_KEY"]},
            json={"systemInstruction": {"parts": [{"text": system}]},
                  "contents": [{"role": "user", "parts": [{"text": user}]}],
                  "generationConfig": {"responseMimeType": "application/json",
                                       "maxOutputTokens": max_tokens}},
            timeout=90)
        r.raise_for_status()
        text = r.json()["candidates"][0]["content"]["parts"][0]["text"]
    else:
        raise RuntimeError("No LLM API key configured")
    return _extract_json(text)
