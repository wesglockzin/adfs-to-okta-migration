import io
import urllib.error

import pytest

import llm_client

NAMES = ("LLM_BASE_URL", "LLM_MODEL_REASON", "LLM_MODEL_FAST", "LLM_MODEL_EMBED")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in NAMES:
        monkeypatch.delenv(name, raising=False)


def test_missing_base_url_names_the_setting():
    with pytest.raises(RuntimeError, match="LLM_BASE_URL"):
        llm_client.ask("hi")


def test_missing_model_names_the_setting(monkeypatch):
    monkeypatch.setenv("LLM_BASE_URL", "http://llm.example.test")
    monkeypatch.setattr(llm_client, "_post", lambda *a, **k: {})
    with pytest.raises(RuntimeError, match="LLM_MODEL_REASON"):
        llm_client.ask("hi")


def test_health_reports_missing_settings_instead_of_raising():
    result = llm_client.health()
    assert result["status"] == "error"
    assert "LLM_MODEL" in result["detail"] or "LLM_BASE_URL" in result["detail"]


def test_http_error_reports_status_and_body(monkeypatch):
    monkeypatch.setenv("LLM_BASE_URL", "http://llm.example.test")
    err = urllib.error.HTTPError(
        "http://llm.example.test/x", 503, "bad", {}, io.BytesIO(b"model loading")
    )

    def fail(*_args, **_kwargs):
        raise err

    monkeypatch.setattr(llm_client.urllib.request, "urlopen", fail)
    with pytest.raises(RuntimeError) as exc:
        llm_client._post("/v1/chat/completions", {})
    assert "503" in str(exc.value)
    assert "model loading" in str(exc.value)
