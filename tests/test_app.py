import importlib
import io
import json
import sys
import zipfile
import zlib

import pytest
import requests

from settings import ConfigError

SETTING_NAMES = (
    "AUTH_MODE",
    "OIDC_ISSUER",
    "OIDC_CLIENT_ID",
    "OIDC_CLIENT_SECRET",
    "FLASK_SECRET_KEY",
    "ALLOWED_USERS",
    "ALLOWED_GROUPS",
)
ORIGIN = {"Origin": "http://localhost"}


@pytest.fixture
def load_app(monkeypatch):
    # Keep a developer's local .env file from refilling the settings.
    monkeypatch.setattr("dotenv.load_dotenv", lambda *args, **kwargs: False)

    def load(**env):
        for name in SETTING_NAMES:
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("OKTA_ENVIRONMENTS", "dev=https://okta.example.test")
        monkeypatch.delenv("OKTA_DEV_API_TOKEN", raising=False)
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
    records = [
        r.getMessage()
        for r in caplog.records
        if "OIDC sign-in error from provider" in r.getMessage()
    ]
    assert records, "the provider error must be logged"
    assert all("\n" not in m for m in records)
    assert "\\n" in records[0]


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
        headers=ORIGIN,
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
        headers=ORIGIN,
    )
    body = resp.get_data(as_text=True)
    assert '"type": "error"' in body
    assert body.rstrip().endswith('"type": "done"}')


def test_auth_mode_none_leaves_gate_open(load_app):
    client = load_app(AUTH_MODE="none").app.test_client()
    assert client.get("/health").status_code == 200
    assert client.get("/login").status_code == 200


def test_index_lists_configured_environments_and_defaults_to_first(load_app):
    module = load_app(
        AUTH_MODE="none",
        OKTA_ENVIRONMENTS="test=https://a.example.test,live=https://b.example.test",
    )
    html = module.app.test_client().get("/").get_data(as_text=True)
    assert 'value="test" checked' in html
    assert 'value="live"' in html
    assert 'value="dev"' not in html
    assert 'value="prod"' not in html
    assert module.DEFAULT_ENV == "test"


def test_app_refuses_to_start_without_okta_environments(load_app, monkeypatch):
    module = load_app(AUTH_MODE="none")  # sets the variable; now remove it
    monkeypatch.delenv("OKTA_ENVIRONMENTS")
    sys.modules.pop("app", None)
    del module
    with pytest.raises(ConfigError, match="OKTA_ENVIRONMENTS"):
        importlib.import_module("app")


@pytest.mark.parametrize("headers", [{}, {"Origin": "http://evil.example"}])
def test_post_without_same_site_origin_is_rejected(load_app, headers):
    client = load_app(AUTH_MODE="none").app.test_client()
    resp = client.post("/api/analyze-scan", json={"results": []}, headers=headers)
    assert resp.status_code == 403


def _callback_user(module, monkeypatch, userinfo):
    monkeypatch.setattr(
        module.oauth.okta, "authorize_access_token", lambda: {"userinfo": userinfo}
    )
    client = module.app.test_client()
    client.get("/oidc/callback?code=x&state=y")
    with client.session_transaction() as sess:
        return sess.get("user")


def test_allow_list_refuses_unlisted_user(load_app, monkeypatch):
    module = load_app(ALLOWED_USERS="ok@example.test", **OIDC_ENV)
    assert _callback_user(module, monkeypatch, {"email": "other@example.test"}) is None


def test_allow_list_admits_listed_user_and_group_member(load_app, monkeypatch):
    module = load_app(
        ALLOWED_USERS="ok@example.test", ALLOWED_GROUPS="admins", **OIDC_ENV
    )
    assert _callback_user(module, monkeypatch, {"email": "OK@example.test"})
    member = {"email": "x@example.test", "groups": ["Admins"]}
    assert _callback_user(module, monkeypatch, member)


def test_zip_with_parent_directory_entry_is_rejected(load_app, monkeypatch, tmp_path):
    module = load_app(AUTH_MODE="none")
    upload_root = tmp_path / "uploads"
    upload_root.mkdir()
    monkeypatch.setattr(module, "UPLOAD_ROOT", upload_root)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../escaped.txt", "x")
        zf.writestr("../extracted_sibling/x.txt", "x")
    resp = module.app.test_client().post(
        "/api/upload",
        data={"file": (io.BytesIO(buf.getvalue()), "export.zip")},
        content_type="multipart/form-data",
        headers=ORIGIN,
    )
    assert resp.status_code == 400
    assert not (tmp_path / "escaped.txt").exists()
    assert list(upload_root.iterdir()) == []


def test_analyze_scan_sorts_results_into_sections(load_app):
    module = load_app(AUTH_MODE="none")
    results = [
        {"app_name": "Ready", "acs_count": 2},
        {"app_name": "Flagged", "acs_count": 1, "requires_review": True},
        {"app_name": "NoAcs", "acs_count": 0},
        {"app_name": "Broken", "parse_error": "x"},
        {"app_name": "Drift", "acs_count": 2, "in_okta": True, "okta_acs_count": 1},
        {"app_name": "NoSigning", "acs_count": 1, "has_enc_cert": True},
    ]
    resp = module.app.test_client().post(
        "/api/analyze-scan", json={"results": results}, headers=ORIGIN
    )
    first = resp.get_data(as_text=True).split("\n\n")[0]
    sections = json.loads(first.removeprefix("data: "))["data"]
    assert "Ready" in sections["ready"]
    assert "Flagged" not in sections["ready"]
    assert "NoAcs" in sections["no_acs"]
    assert "Broken" not in sections["no_acs"]
    assert sections["parse_errors"] == ["Broken"]
    assert sections["acs_mismatch"] == [{"app_name": "Drift", "adfs": 2, "okta": 1}]
    assert sections["cert_gaps"][0]["app_name"] == "NoSigning"


OKTA_BODY = "okta-body-secret-xyz"


class FailingOkta:
    """Fake Okta client whose calls fail with an HTTP 500 carrying a body."""

    def __init__(self, *args, **kwargs):
        pass

    def _fail(self, *args, **kwargs):
        resp = requests.Response()
        resp.status_code = 500
        resp._content = OKTA_BODY.encode()
        raise requests.HTTPError(OKTA_BODY, response=resp)

    list_access_policies = get_all_apps = find_app_by_label = create_saml_app = _fail


@pytest.fixture
def failing_okta(load_app, monkeypatch, tmp_path):
    module = load_app(AUTH_MODE="none")
    monkeypatch.setattr(module, "OktaClient", FailingOkta)
    monkeypatch.setattr(module, "get_token", lambda name: "fake")
    monkeypatch.setattr(module, "LOG_DIR", tmp_path)
    return module


def test_policies_http_error_does_not_reach_client(failing_okta):
    resp = failing_okta.app.test_client().get("/api/policies?env=dev")
    assert resp.status_code == 502
    assert "HTTP 500" in resp.get_json()["error"]
    assert OKTA_BODY not in resp.get_data(as_text=True)


def test_scan_http_error_does_not_reach_client(failing_okta, tmp_path):
    resp = failing_okta.app.test_client().get(f"/api/scan?env=dev&input_dir={tmp_path}")
    assert resp.status_code == 502
    assert OKTA_BODY not in resp.get_data(as_text=True)


def test_import_http_error_is_streamed_without_body(
    failing_okta, monkeypatch, tmp_path
):
    folder = tmp_path / "app1"
    folder.mkdir()
    (folder / "x_config.txt").write_text("x")
    cfg = {"app_name": "App1", "acs_endpoints": [], "assign_everyone": False}
    monkeypatch.setattr(failing_okta, "parse_config", lambda path: cfg)
    monkeypatch.setattr(FailingOkta, "find_app_by_label", lambda self, name: None)
    resp = failing_okta.app.test_client().post(
        "/api/import",
        json={"env": "dev", "input_dir": str(tmp_path), "apps": ["app1"]},
        headers=ORIGIN,
    )
    body = resp.get_data(as_text=True)
    assert '"status": "error"' in body
    assert "HTTP 500" in body
    assert OKTA_BODY not in body


def test_run_detail_rejects_query_injection_in_run_id(failing_okta, monkeypatch):
    queries = []
    monkeypatch.setattr(failing_okta, "LA_QUERY_ENABLED", True)
    monkeypatch.setattr(
        failing_okta, "_query_la", lambda kql, days=365: queries.append(kql) or []
    )
    resp = failing_okta.app.test_client().get("/api/logs/x'%20or%201==1%20or%20r=='")
    assert resp.status_code == 400
    assert queries == []


def test_local_run_log_is_served_and_escapes_are_refused(failing_okta, monkeypatch, tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "import_okta prod_2026-11-13.json").write_text('{"run": 1}')
    (tmp_path / "secret.json").write_text("{}")
    monkeypatch.setattr(failing_okta, "LOG_DIR", logs)
    monkeypatch.setattr(failing_okta, "LA_QUERY_ENABLED", False)
    client = failing_okta.app.test_client()
    ok = client.get("/api/logs/import_okta%20prod_2026-11-13.json")
    assert ok.status_code == 200
    assert ok.get_json() == {"run": 1}
    assert client.get("/api/logs/..").status_code == 400
    assert client.get("/api/logs/.").status_code == 404
    assert client.get("/api/logs/missing.json").status_code == 404


def test_sibling_folder_with_same_prefix_is_not_a_run_log(failing_okta, monkeypatch, tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    (tmp_path / "logs_other").mkdir()
    (tmp_path / "logs_other" / "x.json").write_text("{}")
    monkeypatch.setattr(failing_okta, "LOG_DIR", logs)
    monkeypatch.setattr(failing_okta, "LA_QUERY_ENABLED", False)
    resp = failing_okta.app.test_client().get("/api/logs/..%2Flogs_other%2Fx.json")
    assert resp.status_code in (400, 404)


def test_environment_name_needing_encoding_reaches_policies_intact(load_app, monkeypatch):
    module = load_app(
        AUTH_MODE="none", OKTA_ENVIRONMENTS="a&b=https://a.example.test"
    )
    seen = []

    def fake_token(name):
        seen.append(name)
        return "fake"

    monkeypatch.setattr(module, "OktaClient", FailingOkta)
    monkeypatch.setattr(module, "get_token", fake_token)
    client = module.app.test_client()
    page = client.get("/").get_data(as_text=True)
    assert "?env=${encodeURIComponent(env)}" in page
    assert page.count("encodeURIComponent(env)") >= 2
    client.get("/api/policies?env=a%26b")
    assert seen == ["OKTA_A_B_API_TOKEN"]


def test_run_history_from_log_analytics_carries_updated_count(
    failing_okta, monkeypatch
):
    queries = []
    row = {
        "run_id_s": "abc",
        "env_s": "dev",
        "kind_s": "summary",
        "summary_created_d": 0,
        "summary_updated_d": 3,
        "summary_skipped_d": 0,
        "summary_error_d": 0,
    }

    def fake_query(kql, days=365):
        queries.append(kql)
        return [row]

    monkeypatch.setattr(failing_okta, "LA_QUERY_ENABLED", True)
    monkeypatch.setattr(failing_okta, "_query_la", fake_query)
    client = failing_okta.app.test_client()
    listing = client.get("/api/logs").get_json()
    detail = client.get("/api/logs/abc").get_json()
    assert listing[0]["summary"]["updated"] == 3
    assert detail["summary"]["updated"] == 3
    assert len(queries) == 2
    assert all(
        'summary_updated_d = column_ifexists("summary_updated_d", real(0))' in q
        for q in queries
    )


def test_import_counts_updated_apps_separately(failing_okta, monkeypatch, tmp_path):
    folder = tmp_path / "app1"
    folder.mkdir()
    (folder / "x_config.txt").write_text("x")
    cfg = {"app_name": "App1", "acs_endpoints": [], "assign_everyone": False}
    monkeypatch.setattr(failing_okta, "parse_config", lambda path: cfg)
    monkeypatch.setattr(
        FailingOkta, "find_app_by_label", lambda self, name: {"id": "abc123"}
    )
    resp = failing_okta.app.test_client().post(
        "/api/import",
        json={
            "env": "dev",
            "input_dir": str(tmp_path),
            "apps": ["app1"],
            "update_existing": True,
        },
        headers=ORIGIN,
    )
    done = next(
        json.loads(line[len("data: ") :])
        for line in resp.get_data(as_text=True).splitlines()
        if line.startswith("data: ") and '"type": "done"' in line
    )
    assert done["summary"]["updated"] == 1
    assert done["summary"]["created"] == 0
