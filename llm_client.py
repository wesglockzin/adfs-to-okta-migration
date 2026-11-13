"""
Identity tooling — LLM Client
All LLM calls (OpenAI-compatible server, e.g. Ollama) route through here.
Set LLM_BASE_URL, LLM_MODEL_REASON, LLM_MODEL_FAST and LLM_MODEL_EMBED.

Usage:
    from llm_client import ask, ask_stream, embed

    # Single response
    result = ask("Explain this SAML assertion", context=xml_string)

    # Streaming response (for Flask SSE endpoints)
    for chunk in ask_stream("Analyze this claim rule", context=rule_text):
        yield chunk

    # Embedding (for RAG / semantic search)
    vector = embed("Okta routing rule for group finance-users")
"""

import json
import os
import urllib.error
import urllib.request
from collections.abc import Generator

# ── Config ────────────────────────────────────────────────────────────────────
# No defaults: the server URL and model names must be set in the environment.

MODEL_VARS = {
    "reason": "LLM_MODEL_REASON",  # Deep analysis, policy reasoning
    "fast": "LLM_MODEL_FAST",  # Quick queries, config parsing
    "embed": "LLM_MODEL_EMBED",  # Embeddings
}


def _require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is not set")
    return value


def _base() -> str:
    return _require("LLM_BASE_URL").rstrip("/")


def _model(key: str) -> str:
    """Resolve "reason"/"fast"/"embed" to the configured model; other names pass through."""
    if key in MODEL_VARS:
        return _require(MODEL_VARS[key])
    return key

SYSTEM_PROMPT = """You are an expert Identity and Access Management analyst with deep knowledge of:
- Active Directory (AD) and ADFS claim rules, relying party trusts, federation metadata
- Okta: SAML/OIDC app integrations, routing rules, sign-on policies, attribute mappings
- SAML 2.0 and OIDC protocol mechanics
- Security posture analysis for SSO/MFA configurations

Be precise and concise. When analyzing configuration data, flag anomalies, misconfigurations,
and security concerns directly. Use IAM terminology accurately."""


# ── Core request helper ───────────────────────────────────────────────────────

def _post(path: str, payload: dict) -> dict:
    """Raw HTTP POST to Ollama — no external dependencies required."""
    base = _base()
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{base}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:500]
        raise RuntimeError(f"LLM server returned HTTP {e.code}: {body}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"LLM server unreachable at {base} ({e})") from e


def _post_stream(path: str, payload: dict) -> Generator[str, None, None]:
    """Streaming POST — yields content chunks as they arrive."""
    base = _base()
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{base}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            for raw_line in resp:
                line = raw_line.decode().strip()
                if not line or line == "data: [DONE]":
                    continue
                line = line.removeprefix("data: ")
                chunk = json.loads(line)
                delta = chunk.get("choices", [{}])[0].get("delta", {}).get("content", "")
                if delta:
                    yield delta
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:500]
        raise RuntimeError(f"LLM server returned HTTP {e.code}: {body}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"LLM server unreachable at {base} ({e})") from e


# ── Public API ────────────────────────────────────────────────────────────────

def ask(
    prompt: str,
    context: str = "",
    model: str = "reason",
    system: str = SYSTEM_PROMPT,
) -> str:
    """
    Send a prompt to the local LLM and return the full response.

    Args:
        prompt:  The question or instruction.
        context: Raw data to analyze (SAML XML, JSON, log lines, etc.).
                 Appended to the prompt automatically.
        model:   "reason" (72B, default) or "fast" (32B).
        system:  Override the system prompt if needed.

    Returns:
        The model's response as a string.
    """
    _base()  # fail first on a missing server URL
    full_prompt = f"{prompt}\n\n{context}".strip() if context else prompt
    payload = {
        "model": _model(model),
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": full_prompt},
        ],
        "stream": False,
    }
    result = _post("/v1/chat/completions", payload)
    return result["choices"][0]["message"]["content"]


def ask_stream(
    prompt: str,
    context: str = "",
    model: str = "reason",
    system: str = SYSTEM_PROMPT,
) -> Generator[str, None, None]:
    """
    Streaming version of ask(). Yields content chunks as they arrive.
    Use this for Flask SSE endpoints so the UI updates in real time.

    Example (Flask):
        @app.route("/analyze")
        def analyze():
            def generate():
                for chunk in ask_stream("Analyze this SAML assertion", context=xml):
                    yield f"data: {chunk}\n\n"
            return Response(generate(), mimetype="text/event-stream")
    """
    _base()  # fail first on a missing server URL
    full_prompt = f"{prompt}\n\n{context}".strip() if context else prompt
    payload = {
        "model": _model(model),
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": full_prompt},
        ],
        "stream": True,
    }
    yield from _post_stream("/v1/chat/completions", payload)


def embed(text: str) -> list[float]:
    """
    Generate an embedding vector for the given text.
    Used for semantic search / RAG over identity configs and logs.

    Args:
        text: The text to embed (config snippet, log line, policy description, etc.)

    Returns:
        A list of floats representing the embedding vector.
    """
    _base()  # fail first on a missing server URL
    payload = {
        "model": _model("embed"),
        "input": text,
    }
    result = _post("/v1/embeddings", payload)
    return result["data"][0]["embedding"]


def health() -> dict:
    """Check the LLM server and confirm the configured models are available."""
    try:
        models = {k: _model(k) for k in MODEL_VARS}
        req = urllib.request.Request(f"{_base()}/api/tags")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
    except (RuntimeError, urllib.error.URLError, OSError, ValueError) as e:
        return {"status": "error", "detail": str(e)}
    available = {m["name"] for m in data.get("models", [])}
    return {
        "status": "ok",
        "available_models": sorted(available),
        "expected": models,
        "missing": [v for v in models.values() if not any(v in a for a in available)],
    }
