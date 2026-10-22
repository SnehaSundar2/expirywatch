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


_discovered = {}


def _gemini_pick():
    """Ask Google which models this key can use and pick a current Flash model."""
    if "gemini" in _discovered:
        return _discovered["gemini"]
    try:
        r = requests.get("https://generativelanguage.googleapis.com/v1beta/models?pageSize=200",
                         headers={"x-goog-api-key": os.environ["GEMINI_API_KEY"]}, timeout=20)
        r.raise_for_status()
        names = [m["name"].split("/")[-1] for m in r.json().get("models", [])
                 if "generateContent" in m.get("supportedGenerationMethods", [])]
        flash = [n for n in names if "flash" in n and not any(w in n for w in ("image", "tts", "audio", "live", "exp", "preview", "thinking"))]
        pick = sorted(flash or names, key=lambda n: ("lite" in n, [-int(x) if x.isdigit() else 0 for x in re.split(r"[-.]", n)]))[0]
    except Exception:
        pick = DEFAULTS["gemini"]
    _discovered["gemini"] = pick
    return pick


def model_name():
    p = provider()
    if os.getenv("LLM_MODEL"):
        return os.environ["LLM_MODEL"]
    if p == "gemini" and "gemini" in _discovered:
        return _discovered["gemini"]
    return DEFAULTS.get(p, "none")


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
        if not os.getenv("LLM_MODEL"):
            model = _gemini_pick()
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
