import importlib
import io
import sys
import zipfile
import zlib

import pytest

from settings import ConfigError

SETTING_NAMES = (
    "AUTH_MODE",
    "OIDC_ISSUER",
    "OIDC_CLIENT_ID",
    "OIDC_CLIENT_SECRET",
    "FLASK_SECRET_KEY",
)


@pytest.fixture
def load_app(monkeypatch):
    # Keep a developer's local .env file from refilling the settings.
    monkeypatch.setattr("dotenv.load_dotenv", lambda *args, **kwargs: False)

    def load(**env):
        for name in SETTING_NAMES:
            monkeypatch.delenv(name, raising=False)
        for name, value in env.items():
            monkeypatch.setenv(name, value)
        sys.modules.pop("app", None)
        return importlib.import_module("app")

    yield load
    sys.modules.pop("app", None)


OIDC_ENV = {
    "OIDC_ISSUER": "https://issuer.example.test",
    "OIDC_CLIENT_ID": "test-id-not-real",
    "OIDC_CLIENT_SECRET": "test-secret-not-real",
    "FLASK_SECRET_KEY": "test-key-not-real",
}


def test_app_refuses_to_start_without_auth_settings(load_app):
    with pytest.raises(ConfigError):
        load_app()


def test_health_is_public_and_makes_no_outbound_calls(load_app, monkeypatch):
    client = load_app(**OIDC_ENV).app.test_client()

    def no_outbound(*args, **kwargs):
        raise AssertionError("/health made an outbound call")

    monkeypatch.setattr("urllib.request.urlopen", no_outbound)
    monkeypatch.setattr("requests.Session.send", no_outbound)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_gate_blocks_anonymous_requests(load_app):
    client = load_app(**OIDC_ENV).app.test_client()
    assert client.get("/api/scan").status_code == 401
    page = client.get("/")
    assert page.status_code == 302
    assert "/login" in page.headers["Location"]


def test_login_ignores_offsite_next(load_app):
    client = load_app(**OIDC_ENV).app.test_client()
    client.get("/login?next=//evil.example")
    with client.session_transaction() as sess:
        assert "post_login_redirect" not in sess


def test_login_keeps_relative_next(load_app):
    client = load_app(**OIDC_ENV).app.test_client()
    client.get("/login?next=/logs")
    with client.session_transaction() as sess:
        assert sess["post_login_redirect"] == "/logs"


def test_login_page_hides_raw_provider_error(load_app):
    client = load_app(**OIDC_ENV).app.test_client()
    resp = client.get(
        "/oidc/callback?error=server_error&error_description=secret-detail-xyz"
    )
    assert resp.status_code == 302
    page = client.get("/login")
    body = page.get_data(as_text=True)
    assert "secret-detail-xyz" not in body
    assert "server_error" not in body
    assert "Sign-in failed" in body


def test_login_page_shows_access_denied_notice_without_raw_text(load_app):
    client = load_app(**OIDC_ENV).app.test_client()
    client.get("/oidc/callback?error=access_denied&error_description=raw-detail-xyz")
    body = client.get("/login").get_data(as_text=True)
    assert "Access denied" in body
    assert "raw-detail-xyz" not in body


def test_token_exchange_failure_hides_exception_text(load_app, monkeypatch):
    module = load_app(**OIDC_ENV)

    def boom(*args, **kwargs):
        raise RuntimeError("token-endpoint-detail-xyz")

    monkeypatch.setattr(module.oauth.okta, "authorize_access_token", boom)
    client = module.app.test_client()
    resp = client.get("/oidc/callback?code=x&state=y")
    assert resp.status_code == 302
    body = client.get("/login").get_data(as_text=True)
    assert "token-endpoint-detail-xyz" not in body
    assert "Sign-in failed" in body


def test_provider_error_log_cannot_forge_lines(load_app, caplog):
    client = load_app(**OIDC_ENV).app.test_client()
    client.get("/oidc/callback?error=x&error_description=ok%0AINFO forged line")
    assert all("\n" not in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("failure", [zlib.error("bad data"), EOFError("short")])
def test_corrupt_zip_returns_400_and_removes_temp_folder(
    load_app, monkeypatch, tmp_path, failure
):
    module = load_app(AUTH_MODE="none")
    monkeypatch.setattr(module, "UPLOAD_ROOT", tmp_path)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("export/a_config.txt", "x" * 100)

    def broken_extract(self, *args, **kwargs):
        raise failure

    monkeypatch.setattr(zipfile.ZipFile, "extractall", broken_extract)
    resp = module.app.test_client().post(
        "/api/upload",
        data={"file": (io.BytesIO(buf.getvalue()), "export.zip")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400
    assert "unzip failed" in resp.get_json()["error"]
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "failure",
    [
        ValueError("bad line"),
        TimeoutError("slow"),
        IndexError("shape"),
        RuntimeError("LLM connection dropped during stream"),
    ],
)
def test_analyze_scan_reports_stream_failures_and_finishes(
    load_app, monkeypatch, failure
):
    module = load_app(AUTH_MODE="none")

    def broken_stream(prompt, model=None):
        yield "partial"
        raise failure

    monkeypatch.setattr(module, "LLM_AVAILABLE", True)
    monkeypatch.setattr(module, "llm_ask_stream", broken_stream)
    resp = module.app.test_client().post(
        "/api/analyze-scan",
        json={"results": [{"app_name": "App", "requires_review": True}]},
    )
    body = resp.get_data(as_text=True)
    assert '"type": "error"' in body
    assert body.rstrip().endswith('"type": "done"}')


def test_auth_mode_none_leaves_gate_open(load_app):
    client = load_app(AUTH_MODE="none").app.test_client()
    assert client.get("/health").status_code == 200
    assert client.get("/login").status_code == 200
