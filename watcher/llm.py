"""Small provider-agnostic LLM client. Uses whichever key is set in .env:
ANTHROPIC_API_KEY, OPENAI_API_KEY or GEMINI_API_KEY. LLM_MODEL overrides the model.
With no key, available() is False and the agent runs on its rule-based brain."""
import json
import os
import re
import time

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
GEMINI_TIMEOUT = float(os.getenv("GEMINI_TIMEOUT", "30"))


def _gemini_candidates():
    """Ask Google which models this key can use; return current Flash models, newest first."""
    if "list" in _discovered:
        return _discovered["list"]
    try:
        r = requests.get("https://generativelanguage.googleapis.com/v1beta/models?pageSize=200",
                         headers={"x-goog-api-key": os.environ["GEMINI_API_KEY"]}, timeout=20)
        r.raise_for_status()
        names = [m["name"].split("/")[-1] for m in r.json().get("models", [])
                 if "generateContent" in m.get("supportedGenerationMethods", [])]
        flash = [n for n in names if "flash" in n and not any(w in n for w in ("image", "tts", "audio", "live", "exp", "preview", "thinking"))]
        ordered = sorted(flash or names, key=lambda n: ("lite" in n, [-int(x) if x.isdigit() else 0 for x in re.split(r"[-.]", n)]))
    except Exception:
        ordered = [DEFAULTS["gemini"]]
    _discovered["list"] = ordered[:8] or [DEFAULTS["gemini"]]
    return _discovered["list"]


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
        models = [os.environ["LLM_MODEL"]] if os.getenv("LLM_MODEL") else (
            ([_discovered["gemini"]] if "gemini" in _discovered else []) + _gemini_candidates())
        last = None
        r, errors = None, []
        for m in dict.fromkeys(models):  # busy, slow or retired model -> retry once, then try the next one
            for attempt in range(2):
                try:
                    r = requests.post(
                        f"https://generativelanguage.googleapis.com/v1beta/models/{m}:generateContent",
                        headers={"x-goog-api-key": os.environ["GEMINI_API_KEY"]},
                        json={"systemInstruction": {"parts": [{"text": system}]},
                              "contents": [{"role": "user", "parts": [{"text": user}]}],
                              "generationConfig": {"responseMimeType": "application/json",
                                                   "maxOutputTokens": max(max_tokens, 4096)}},
                        timeout=GEMINI_TIMEOUT)
                except requests.RequestException as e:
                    r = None
                    errors.append(f"{m}: {type(e).__name__}")
                    break
                if r.status_code in (429, 500, 503) and attempt == 0:
                    time.sleep(2)
                    continue
                break
            if r is not None and r.status_code == 200:
                _discovered["gemini"] = m
                break
            if r is not None:
                errors.append(f"{m}: HTTP {r.status_code}")
            r = None
        if r is None:
            raise RuntimeError("No Gemini model answered (" + "; ".join(errors[-6:]) + ")")
        parts = r.json()["candidates"][0]["content"]["parts"]
        text = "".join(p_.get("text", "") for p_ in parts)
    else:
        raise RuntimeError("No LLM API key configured")
    return _extract_json(text)


def diagnose():
    """Which models answer for this key (never returns the key)."""
    out = {"provider": provider(), "candidates": _gemini_candidates() if provider() == "gemini" else [model_name()]}
    results = []
    for m in out["candidates"][:8]:
        try:
            if provider() != "gemini":
                chat_json("Reply with JSON.", 'Return {"ok": true}')
                results.append({"model": m, "ok": True})
                break
            r = requests.post(f"https://generativelanguage.googleapis.com/v1beta/models/{m}:generateContent",
                              headers={"x-goog-api-key": os.environ["GEMINI_API_KEY"]},
                              json={"contents": [{"role": "user", "parts": [{"text": 'Reply with exactly {"ok": true}'}]}],
                                    "generationConfig": {"responseMimeType": "application/json"}}, timeout=GEMINI_TIMEOUT)
            results.append({"model": m, "status": r.status_code, "reply": r.text[:160] if r.status_code != 200 else "ok"})
        except Exception as e:
            results.append({"model": m, "error": type(e).__name__})
    out["results"] = results
    return out
