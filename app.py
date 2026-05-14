"""
app.py — ADFS → Okta Migration Tool

Local run:    .venv/bin/python app.py     # http://localhost:5001
ACA URL:      https://adfs-okta-migration.your-env.eastus.azurecontainerapps.io

Auth posture (v2.0.0+):
  PROD Okta OIDC gate via the shared "Okta Admin Tools" app. Authlib drives
  the OAuth flow and validates the id_token. If any of the OIDC env vars is
  missing the gate disables itself (open posture) so the tool stays usable
  when running locally without OIDC.

Input flow (v2.0.0+):
  - In ACA: user uploads a ZIP of an ADFS export. POST /api/upload extracts
    the archive into a per-session tempdir; subsequent /api/scan and
    /api/import use the unpacked path. The export script itself is owned by
    this project (scripts/Export-ADFSRelyingPartyTrusts.ps1) and downloadable
    from /download/export-script.
  - Locally: the legacy browse-to-folder workflow still works (osascript
    folder picker) for parity with pre-2.0 behavior.

Logging (v2.0.0+):
  Each import event is shipped to the Azure Log Analytics workspace via the
  HTTP Data Collector API into the custom table ADFSImportRuns_CL. The /logs
  page queries the same workspace via the Azure Monitor Query SDK (managed
  identity, Log Analytics Reader role). Local-dev falls back to the legacy
  per-run JSON files in logs/ when LA env vars are not set.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import requests as req_lib
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from flask import (
    Flask, jsonify, redirect, render_template, render_template_string,
    request, Response, send_file, session, stream_with_context, url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                    handlers=[logging.StreamHandler(sys.stdout)])
log = logging.getLogger("adfs-okta")

try:
    import keyring as _keyring
    KEYRING_SERVICE = "adfs-okta-migration"
except ImportError:
    _keyring = None  # type: ignore
    KEYRING_SERVICE = ""


def get_token(var_name: str) -> str:
    if _keyring:
        try:
            val = _keyring.get_password(KEYRING_SERVICE, var_name)
            if val:
                return val.strip()
        except Exception:
            pass  # Linux ACA containers have no keyring backend — fall through
    return os.environ.get(var_name, "").strip()


load_dotenv(Path(__file__).parent / ".env")

sys.path.insert(0, str(Path(__file__).parent))
from okta_saml_import import (
    OKTA_ADMIN_ENVIRONMENTS,
    OktaClient,
    load_cert,
    parse_config,
)

try:
    from llm_client import ask_stream as llm_ask_stream
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False
    llm_ask_stream = None

APP_VERSION = "2.0.8"

# ── OIDC config (PROD Okta via "Okta Admin Tools" app) ───────────────────────
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32).hex()
OIDC_ISSUER = os.environ.get("OIDC_ISSUER", "").rstrip("/")
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "")
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:5001").rstrip("/")
OIDC_SCOPES = "openid email profile"
OIDC_ENABLED = bool(OIDC_ISSUER and OIDC_CLIENT_ID and OIDC_CLIENT_SECRET)

if not OIDC_ENABLED:
    log.warning("OIDC is NOT configured — auth gate disabled, app is open. "
                "Set OIDC_ISSUER / OIDC_CLIENT_ID / OIDC_CLIENT_SECRET to enable.")

# ── Log Analytics config (Data Collector write + Monitor Query read) ────────
LA_WORKSPACE_ID = os.environ.get("LA_WORKSPACE_ID", "").strip()
LA_WORKSPACE_KEY = os.environ.get("LA_WORKSPACE_KEY", "").strip()
LA_TABLE_NAME = os.environ.get("LA_TABLE_NAME", "ADFSImportRuns")
LA_RESOURCE_ID = os.environ.get("LA_RESOURCE_ID", "").strip()  # /subscriptions/.../workspaces/<ws> for query
LA_WRITE_ENABLED = bool(LA_WORKSPACE_ID and LA_WORKSPACE_KEY)
LA_QUERY_ENABLED = bool(LA_WORKSPACE_ID and LA_RESOURCE_ID)

if not LA_WRITE_ENABLED:
    log.info("Log Analytics write DISABLED — falling back to per-run JSON files in logs/.")

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024 * 1024  # 256 MB upload cap
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = APP_BASE_URL.startswith("https://")
app.config["SESSION_COOKIE_HTTPONLY"] = True

oauth = OAuth(app)
if OIDC_ENABLED:
    oauth.register(
        name="okta",
        client_id=OIDC_CLIENT_ID,
        client_secret=OIDC_CLIENT_SECRET,
        server_metadata_url=f"{OIDC_ISSUER}/.well-known/openid-configuration",
        client_kwargs={"scope": OIDC_SCOPES, "code_challenge_method": "S256"},
    )

PUBLIC_PATHS = {
    "/health", "/login", "/oidc/login", "/oidc/callback", "/logout", "/favicon.ico",
}


@app.before_request
def _auth_gate():
    if not OIDC_ENABLED:
        return
    if request.path.startswith("/static/") or request.path in PUBLIC_PATHS:
        return
    if not session.get("user"):
        if request.path.startswith("/api/"):
            return jsonify(error="unauthorized — session expired"), 401
        return redirect(url_for("login", next=request.path))


# ── Local fallback log dir (used when LA write is disabled) ─────────────────
LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

# ── Upload session storage (per-replica scratch on container disk) ──────────
UPLOAD_ROOT = Path(tempfile.gettempdir()) / "adfs-uploads"
UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
UPLOAD_TTL_SECONDS = 4 * 60 * 60  # 4 hours

# Map session_id → unpacked path (in-memory, single replica)
_upload_sessions: dict[str, str] = {}
_upload_lock = threading.Lock()


def _evict_expired_uploads() -> None:
    """Drop unpacked sessions older than UPLOAD_TTL_SECONDS."""
    now = time.time()
    with _upload_lock:
        for sid in list(_upload_sessions):
            p = Path(_upload_sessions[sid])
            try:
                age = now - p.stat().st_mtime if p.exists() else UPLOAD_TTL_SECONDS + 1
            except FileNotFoundError:
                age = UPLOAD_TTL_SECONDS + 1
            if age > UPLOAD_TTL_SECONDS:
                shutil.rmtree(p, ignore_errors=True)
                _upload_sessions.pop(sid, None)


# ── Log Analytics Data Collector helpers ────────────────────────────────────
def _la_signature(workspace_id: str, shared_key: str, date: str,
                  content_length: int, method: str, content_type: str,
                  resource: str) -> str:
    string_to_hash = (
        f"{method}\n{content_length}\n{content_type}\n"
        f"x-ms-date:{date}\n{resource}"
    )
    bytes_to_hash = string_to_hash.encode("utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, hashlib.sha256).digest()
    ).decode("utf-8")
    return f"SharedKey {workspace_id}:{encoded_hash}"


def _la_post(records: list[dict]) -> None:
    """POST a batch of records to Azure Log Analytics Data Collector API.
    Records get the LA_TABLE_NAME log type — appended automatically as
    <table>_CL. Raises on non-2xx; caller handles."""
    if not LA_WRITE_ENABLED or not records:
        return
    body = json.dumps(records).encode("utf-8")
    method = "POST"
    content_type = "application/json"
    resource = "/api/logs"
    rfc_date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    signature = _la_signature(LA_WORKSPACE_ID, LA_WORKSPACE_KEY, rfc_date,
                              len(body), method, content_type, resource)
    url = f"https://host.example.gov}.ods.opinsights.azure.com{resource}?api-version=2016-04-01"
    r = req_lib.post(url, data=body, headers={
        "Content-Type":   content_type,
        "Authorization":  signature,
        "Log-Type":       LA_TABLE_NAME,
        "x-ms-date":      rfc_date,
        "time-generated-field": "ts",
    }, timeout=30)
    if r.status_code >= 300:
        raise RuntimeError(f"LA write failed {r.status_code}: {r.text[:200]}")


def _emit_event(env: str, run_id: str, event: dict) -> None:
    """Record one import event. Writes to LA when configured; otherwise the
    caller handles via per-run JSON file. Always logs to stdout."""
    record = {
        "ts":      datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "env":     env,
        "run_id":  run_id,
        **event,
    }
    log.info("EVENT %s", json.dumps(record))
    if LA_WRITE_ENABLED:
        try:
            _la_post([record])
        except Exception:
            log.exception("LA write failed; event kept in stdout only")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    default_dir = os.environ.get("ADFS_EXPORT_DIR", "")
    # demo=1 unlocks sanitized example data for screenshots. Belt-and-suspenders:
    # also require an authenticated session, so demo never activates for an
    # unauthenticated visitor — even if the global auth gate is ever bypassed
    # (e.g. OIDC env vars missing). The auth gate is the primary control;
    # this is a second line of defense.
    demo = (request.args.get("demo") == "1") and bool(session.get("user"))
    return render_template("index.html",
                           default_dir=default_dir,
                           version=APP_VERSION,
                           upload_only=OIDC_ENABLED,
                           user=session.get("user"),
                           demo=demo)


@app.route("/health")
def health():
    return jsonify(status="ok", version=APP_VERSION), 200


# ── OIDC routes ──────────────────────────────────────────────────────────────
LOGIN_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>ADFS Migration — Sign in</title>
<style>
 body{margin:0;background:#0f172a;color:#e2e8f0;font:14px -apple-system,Segoe UI,Roboto,sans-serif;display:grid;place-items:center;min-height:100vh}
 .card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:40px;max-width:420px;width:90%;text-align:center}
 h1{margin:0 0 8px;font-size:20px}
 p{color:#94a3b8;margin:0 0 28px;font-size:13px}
 a.btn{display:inline-block;background:#22c55e;color:#0f172a;text-decoration:none;padding:10px 22px;border-radius:8px;font-weight:600}
 a.btn:hover{background:#16a34a;color:#fff}
 .err{color:#fca5a5;font-size:12px;margin-top:16px}
 .vpn{background:#1f2937;border:1px solid #f59e0b;color:#fbbf24;font-size:13px;margin-top:20px;padding:12px 14px;border-radius:8px;text-align:left;line-height:1.5}
 .vpn b{color:#fde68a}
 .vpn .raw{display:block;color:#94a3b8;font-size:11px;margin-top:8px;font-family:ui-monospace,Menlo,monospace;word-break:break-word}
 footer{position:fixed;bottom:16px;left:0;right:0;text-align:center;font-size:11px;color:#475569}
</style></head><body>
<div class="card">
 <h1>ADFS → Okta Migration</h1>
 <p>Sign in with your work email to continue.</p>
 <a class="btn" href="/oidc/login">Sign in</a>
 {% if error %}
   {% if 'access_denied' in error %}
   <div class="vpn"><b>VPN required.</b> This app is restricted to the internal network. Connect to AnyConnect, then click Sign in again.<span class="raw">{{ error }}</span></div>
   {% else %}<div class="err">{{ error }}</div>{% endif %}
 {% endif %}
</div>
<footer>ADFS → Okta Migration v{{ version }}</footer>
</body></html>"""


@app.get("/login")
def login():
    if session.get("user"):
        return redirect(url_for("index"))
    nxt = request.args.get("next")
    if nxt:
        session["post_login_redirect"] = nxt
    err = session.pop("login_error", None)
    return render_template_string(LOGIN_HTML, error=err, version=APP_VERSION)


@app.get("/oidc/login")
def oidc_login():
    if not OIDC_ENABLED:
        session["login_error"] = "OIDC not configured"
        return redirect(url_for("login"))
    redirect_uri = url_for("oidc_callback", _external=True)
    return oauth.okta.authorize_redirect(redirect_uri)


@app.get("/oidc/callback")
def oidc_callback():
    if request.args.get("error"):
        session["login_error"] = f"{request.args.get('error')}: {request.args.get('error_description', '')}"
        return redirect(url_for("login"))
    try:
        token = oauth.okta.authorize_access_token()
    except Exception as e:
        log.exception("OIDC token exchange failed")
        session["login_error"] = f"token exchange failed: {e}"
        return redirect(url_for("login"))
    claims = token.get("userinfo") or {}
    email = claims.get("email") or claims.get("preferred_username")
    if not email:
        session["login_error"] = "Email claim missing in id_token."
        return redirect(url_for("login"))
    session["user"] = {
        "email": email,
        "name": claims.get("name"),
        "login_time": datetime.now(timezone.utc).isoformat(),
    }
    redirect_to = session.pop("post_login_redirect", None) or url_for("index")
    return redirect(redirect_to)


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/favicon.ico")
def favicon():
    return ("", 204)


# ── Export script — owned by this project, downloadable from the UI ──────────
@app.get("/download/export-script")
def download_export_script():
    p = Path(__file__).parent / "scripts" / "Export-ADFSRelyingPartyTrusts.ps1"
    if not p.exists():
        return jsonify({"error": "export script not found"}), 404
    return send_file(p, mimetype="text/plain",
                     as_attachment=True, download_name=p.name)


# ── ZIP upload — extracts to per-session tempdir ────────────────────────────
@app.route("/api/upload", methods=["POST"])
def api_upload():
    """Accept an ADFS export ZIP, extract to a per-session tempdir, return the
    session id + unpacked path. Subsequent /api/scan and /api/import use the
    unpacked path as input_dir."""
    _evict_expired_uploads()

    f = request.files.get("file")
    if f is None:
        return jsonify({"error": "no file uploaded (form field 'file')"}), 400
    fname = secure_filename(f.filename or "upload.zip")
    if not fname.lower().endswith(".zip"):
        return jsonify({"error": "only .zip uploads are accepted"}), 400

    sid = uuid.uuid4().hex
    sdir = UPLOAD_ROOT / sid
    sdir.mkdir(parents=True, exist_ok=True)
    zpath = sdir / fname
    f.save(str(zpath))

    extract_dir = sdir / "extracted"
    extract_dir.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(zpath, "r") as zf:
            for member in zf.infolist():
                # Defend against path traversal
                target = (extract_dir / member.filename).resolve()
                if not str(target).startswith(str(extract_dir.resolve())):
                    raise RuntimeError(f"unsafe path in zip: {member.filename}")
            zf.extractall(extract_dir)
    except Exception as e:
        shutil.rmtree(sdir, ignore_errors=True)
        return jsonify({"error": f"unzip failed: {e}"}), 400

    # Find the export root — the zip may contain a single top-level folder
    entries = [p for p in extract_dir.iterdir() if not p.name.startswith(".")]
    if len(entries) == 1 and entries[0].is_dir():
        unpacked = entries[0]
    else:
        unpacked = extract_dir

    with _upload_lock:
        _upload_sessions[sid] = str(unpacked)

    # Count first-level subfolders containing _config.txt as a sanity hint
    folder_count = sum(1 for d in unpacked.iterdir()
                       if d.is_dir() and any(d.glob("*_config.txt")))
    return jsonify({
        "session_id":   sid,
        "path":         str(unpacked),
        "folder_count": folder_count,
        "filename":     fname,
    })


def _resolve_input_dir(input_dir: str, session_id: str) -> tuple[str | None, str | None]:
    """Return (path, error). Prefer session_id when given; fall back to
    explicit input_dir for local-dev parity."""
    if session_id:
        with _upload_lock:
            p = _upload_sessions.get(session_id)
        if not p:
            return None, "upload session not found or expired — please re-upload"
        if not Path(p).is_dir():
            return None, f"session path missing: {p}"
        return p, None
    if not input_dir:
        return None, "input_dir or session_id is required"
    if not Path(input_dir).is_dir():
        return None, f"Directory not found: {input_dir}"
    return input_dir, None


@app.route("/api/browse")
def api_browse():
    """Local-dev only — native macOS folder picker. In ACA this just returns
    a 400 since osascript isn't available."""
    if OIDC_ENABLED or sys.platform != "darwin":
        return jsonify({"error": "browse is local-dev only — use Upload ZIP instead"}), 400
    script = 'POSIX path of (choose folder with prompt "Select ADFS export folder:")'
    try:
        result = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True, text=True, timeout=60
        )
        path = result.stdout.strip().rstrip("/")
        return jsonify({"path": path or ""}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/policies")
def api_policies():
    env = request.args.get("env", "dev")
    if env not in OKTA_ADMIN_ENVIRONMENTS:
        return jsonify({"error": f"Unknown environment: {env}"}), 400
    env_cfg = OKTA_ADMIN_ENVIRONMENTS[env]
    token = get_token(env_cfg["token_var"])
    if not token:
        return jsonify({"error": f"{env_cfg['token_var']} is not set"}), 400
    try:
        client = OktaClient(env_cfg["url"], token)
        policies = client.list_access_policies()
        return jsonify(policies)
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/routing-rules")
def api_routing_rules():
    env = request.args.get("env", "dev")
    if env not in OKTA_ADMIN_ENVIRONMENTS:
        return jsonify({"error": f"Unknown environment: {env}"}), 400
    env_cfg = OKTA_ADMIN_ENVIRONMENTS[env]
    token = get_token(env_cfg["token_var"])
    if not token:
        return jsonify({"error": f"{env_cfg['token_var']} is not set"}), 400
    try:
        client = OktaClient(env_cfg["url"], token)
        rules = client.list_idp_routing_rules()
        return jsonify(rules)
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/scan")
def api_scan():
    """Scan the unpacked export folder and cross-reference against Okta."""
    env = request.args.get("env", "dev")
    input_dir = request.args.get("input_dir", "").strip()
    session_id = request.args.get("session_id", "").strip()

    path, perr = _resolve_input_dir(input_dir, session_id)
    if perr:
        return jsonify({"error": perr}), 400
    if env not in OKTA_ADMIN_ENVIRONMENTS:
        return jsonify({"error": f"Unknown environment: {env}"}), 400

    env_cfg = OKTA_ADMIN_ENVIRONMENTS[env]
    token = get_token(env_cfg["token_var"])
    if not token:
        return jsonify({"error": f"{env_cfg['token_var']} is not set"}), 400

    client = OktaClient(env_cfg["url"], token)

    try:
        okta_apps = client.get_all_apps()
    except Exception as e:
        return jsonify({"error": f"Failed to fetch apps from Okta: {e}"}), 502

    try:
        app_policy_map = client.get_app_policy_map()
    except Exception:
        app_policy_map = {}
    try:
        app_routing_map = client.get_app_routing_rule_map()
    except Exception:
        app_routing_map = {}

    results = []
    root = Path(path)

    for folder in sorted(d for d in root.iterdir() if d.is_dir()):
        config_files = list(folder.glob("*_config.txt"))
        if not config_files:
            continue

        try:
            cfg = parse_config(config_files[0])
        except Exception as e:
            results.append({"folder": folder.name, "app_name": folder.name, "parse_error": str(e)})
            continue

        app_name = cfg["app_name"] or folder.name
        existing = okta_apps.get(app_name)

        okta_id = existing.get("id") if existing else None
        okta_status = existing.get("status") if existing else None
        okta_acs_count = None
        if existing:
            so = existing.get("settings", {}).get("signOn", {})
            okta_acs_count = len(so.get("acsEndpoints", []))

        if cfg["assign_everyone"]:
            group_display = "Everyone"
        elif cfg["assign_groups"]:
            group_display = ", ".join(cfg["assign_groups"])
        else:
            group_display = "—"

        results.append({
            "folder": folder.name,
            "app_name": app_name,
            "acs_count": len(cfg["acs_endpoints"]),
            "has_enc_cert": bool(
                cfg.get("encryption_cert_file")
                and (folder / cfg["encryption_cert_file"]).exists()
            ),
            "has_signing_cert": bool(
                cfg.get("signing_cert_file")
                and (folder / cfg["signing_cert_file"]).exists()
            ),
            "group": group_display,
            "requires_review": cfg.get("requires_review", False),
            "in_okta": existing is not None,
            "okta_id": okta_id,
            "okta_status": okta_status,
            "okta_acs_count": okta_acs_count,
            "okta_policy": app_policy_map.get(okta_id) if okta_id else None,
            "okta_routing_rule": app_routing_map.get(okta_id) if okta_id else None,
        })

    return jsonify(results)


@app.route("/api/toggle-status", methods=["POST"])
def api_toggle_status():
    data = request.get_json()
    env = data.get("env", "dev")
    app_id = data.get("app_id", "").strip()
    action = data.get("action", "")

    if env not in OKTA_ADMIN_ENVIRONMENTS:
        return jsonify({"error": f"Unknown environment: {env}"}), 400
    if action not in ("activate", "deactivate"):
        return jsonify({"error": "action must be 'activate' or 'deactivate'"}), 400

    env_cfg = OKTA_ADMIN_ENVIRONMENTS[env]
    token = get_token(env_cfg["token_var"])
    if not token:
        return jsonify({"error": f"{env_cfg['token_var']} is not set"}), 400

    try:
        client = OktaClient(env_cfg["url"], token)
        if action == "activate":
            client.activate_app(app_id)
        else:
            client.deactivate_app(app_id)
        new_status = "ACTIVE" if action == "activate" else "INACTIVE"
        return jsonify({"status": new_status})
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/import", methods=["POST"])
def api_import():
    """Import selected apps. Streams SSE events: log, progress, done."""
    data = request.get_json()
    env = data.get("env", "dev")
    input_dir = data.get("input_dir", "").strip()
    session_id = data.get("session_id", "").strip()
    folder_names = data.get("apps", [])
    policy_id = data.get("policy_id", "").strip()
    routing_rule_id = data.get("routing_rule_id", "").strip()
    routing_policy_id = data.get("routing_policy_id", "").strip()
    update_existing = bool(data.get("update_existing", False))

    if env not in OKTA_ADMIN_ENVIRONMENTS:
        return jsonify({"error": f"Unknown environment: {env}"}), 400

    path, perr = _resolve_input_dir(input_dir, session_id)
    if perr:
        return jsonify({"error": perr}), 400

    env_cfg = OKTA_ADMIN_ENVIRONMENTS[env]
    token = get_token(env_cfg["token_var"])
    root = Path(path)

    run_ts = datetime.now(timezone.utc)
    run_id = uuid.uuid4().hex

    def generate():
        log_events = []

        def emit(evt_type, **kwargs):
            payload = {"type": evt_type, **kwargs}
            log_events.append(payload)
            # LA: ship every event in the structured form
            _emit_event(env, run_id, {
                "kind":   "event",
                "evt":    evt_type,
                **kwargs,
            })
            return f"data: {json.dumps(payload)}\n\n"

        def save_log(summary):
            # LA: ship a single run-summary record (table column "kind"="summary")
            _emit_event(env, run_id, {
                "kind":           "summary",
                "input_dir":      str(root),
                "apps_requested": folder_names,
                **{f"summary_{k}": v for k, v in (summary or {}).items()},
            })
            # Local-dev fallback only — keep per-run JSON if LA disabled
            if LA_WRITE_ENABLED:
                return
            ts_str = run_ts.strftime("%Y-%m-%d_%H-%M-%S")
            filename = f"import_{env}_{ts_str}.json"
            record = {
                "timestamp": run_ts.isoformat(timespec="seconds"),
                "run_id":    run_id,
                "env":       env,
                "input_dir": str(root),
                "apps_requested": folder_names,
                "summary":   summary,
                "events":    log_events,
            }
            try:
                (LOG_DIR / filename).write_text(json.dumps(record, indent=2))
            except Exception:
                pass

        if not token:
            yield emit("log", level="error", msg=f"{env_cfg['token_var']} is not set")
            summary = {"created": 0, "skipped": 0, "error": len(folder_names)}
            save_log(summary)
            yield emit("done", summary=summary)
            return

        client = OktaClient(env_cfg["url"], token)
        counts = {"created": 0, "skipped": 0, "error": 0}

        for folder_name in folder_names:
            folder = root / folder_name
            config_files = list(folder.glob("*_config.txt"))
            if not config_files:
                yield emit("log", level="warn", msg=f"[{folder_name}] No _config.txt — skipping")
                counts["skipped"] += 1
                yield emit("progress", app=folder_name, status="skipped", msg="No _config.txt found")
                continue

            try:
                cfg = parse_config(config_files[0])
            except Exception as e:
                yield emit("log", level="error", msg=f"[{folder_name}] Parse error: {e}")
                counts["error"] += 1
                yield emit("progress", app=folder_name, status="error", msg=f"Parse error: {e}")
                continue

            app_name = cfg["app_name"] or folder_name
            acs_n = len(cfg["acs_endpoints"])
            yield emit("log", level="info", msg=f"Processing: {app_name}  ({acs_n} ACS endpoints)")

            try:
                existing = client.find_app_by_label(app_name)
            except Exception as e:
                yield emit("log", level="error", msg=f"  ERROR looking up app in Okta: {e}")
                counts["error"] += 1
                yield emit("progress", app=app_name, status="error", msg=f"Okta lookup failed: {e}")
                continue

            if existing:
                if not update_existing:
                    yield emit("log", level="warn",
                               msg=f"  SKIP — already exists in Okta (id={existing['id']})")
                    counts["skipped"] += 1
                    yield emit("progress", app=app_name, status="skipped", okta_id=existing["id"])
                    continue

                okta_id = existing["id"]
                yield emit("log", level="info", msg=f"  UPDATE existing app (id={okta_id})")
                if policy_id:
                    try:
                        client.assign_policy_to_app(okta_id, policy_id)
                        yield emit("log", level="info", msg=f"  Auth policy assigned")
                    except req_lib.HTTPError as e:
                        body = e.response.text if e.response is not None else str(e)
                        yield emit("log", level="warn", msg=f"  Error assigning policy: {body}")
                if routing_rule_id and routing_policy_id:
                    try:
                        client.add_app_to_routing_rule(routing_policy_id, routing_rule_id, okta_id)
                        yield emit("log", level="info", msg=f"  IDP routing rule assigned")
                    except req_lib.HTTPError as e:
                        body = e.response.text if e.response is not None else str(e)
                        yield emit("log", level="warn", msg=f"  Error assigning routing rule: {body}")
                for gname in cfg.get("assign_groups", []):
                    grp = client.find_group_by_name(gname)
                    if grp:
                        try:
                            client.assign_group_to_app(okta_id, grp["id"])
                            yield emit("log", level="info", msg=f"  Assigned group '{gname}'")
                        except req_lib.HTTPError as e:
                            body = e.response.text if e.response is not None else str(e)
                            yield emit("log", level="warn", msg=f"  Error assigning '{gname}': {body}")
                if cfg["assign_everyone"]:
                    grp = client.find_group_by_name("Everyone")
                    if grp:
                        try:
                            client.assign_group_to_app(okta_id, grp["id"])
                            yield emit("log", level="info", msg=f"  Assigned group 'Everyone'")
                        except req_lib.HTTPError as e:
                            body = e.response.text if e.response is not None else str(e)
                            yield emit("log", level="warn", msg=f"  Error assigning 'Everyone': {body}")
                counts["created"] += 1
                yield emit("progress", app=app_name, status="updated", okta_id=okta_id)
                continue

            enc_cert = load_cert(folder, cfg.get("encryption_cert_file"))
            if enc_cert:
                yield emit("log", level="info", msg=f"  Encryption cert: {cfg['encryption_cert_file']}")

            groups_to_assign = []
            if cfg["assign_everyone"]:
                grp = client.find_group_by_name("Everyone")
                if grp:
                    groups_to_assign.append(("Everyone", grp["id"]))
                else:
                    yield emit("log", level="warn", msg="  'Everyone' group not found in Okta")
            for gname in cfg.get("assign_groups", []):
                grp = client.find_group_by_name(gname)
                if grp:
                    groups_to_assign.append((gname, grp["id"]))
                else:
                    yield emit("log", level="warn", msg=f"  Group '{gname}' not found — skipping")

            try:
                result = client.create_saml_app(cfg, enc_cert_pem=enc_cert)
                okta_id = result.get("id")
                yield emit("log", level="info", msg=f"  CREATED → id={okta_id}")
            except req_lib.HTTPError as e:
                body = e.response.text if e.response is not None else str(e)
                yield emit("log", level="error", msg=f"  ERROR: {body}")
                counts["error"] += 1
                try:
                    err_json = json.loads(body)
                    short_msg = err_json.get("errorSummary") or err_json.get("errorCode") or body[:120]
                except Exception:
                    short_msg = body[:120]
                yield emit("progress", app=app_name, status="error", msg=short_msg)
                continue
            except Exception as e:
                yield emit("log", level="error", msg=f"  ERROR (unexpected): {e}")
                counts["error"] += 1
                yield emit("progress", app=app_name, status="error", msg=str(e)[:120])
                continue

            if policy_id:
                try:
                    client.assign_policy_to_app(okta_id, policy_id)
                    yield emit("log", level="info", msg=f"  Auth policy assigned")
                except req_lib.HTTPError as e:
                    body = e.response.text if e.response is not None else str(e)
                    yield emit("log", level="warn", msg=f"  Error assigning policy: {body}")

            if routing_rule_id and routing_policy_id:
                try:
                    client.add_app_to_routing_rule(routing_policy_id, routing_rule_id, okta_id)
                    yield emit("log", level="info", msg=f"  IDP routing rule assigned")
                except req_lib.HTTPError as e:
                    body = e.response.text if e.response is not None else str(e)
                    yield emit("log", level="warn", msg=f"  Error assigning routing rule: {body}")

            for label, gid in groups_to_assign:
                try:
                    client.assign_group_to_app(okta_id, gid)
                    yield emit("log", level="info", msg=f"  Assigned group '{label}'")
                except req_lib.HTTPError as e:
                    body = e.response.text if e.response is not None else str(e)
                    yield emit("log", level="warn", msg=f"  Error assigning '{label}': {body}")

            counts["created"] += 1
            yield emit("progress", app=app_name, status="created", okta_id=okta_id)

        save_log(counts)
        yield emit("done", summary=counts)

    return Response(
        stream_with_context(generate()),
        content_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ---------------------------------------------------------------------------
# AI Analysis route
# ---------------------------------------------------------------------------

@app.route("/api/analyze-scan", methods=["POST"])
def api_analyze_scan():
    """Stream an LLM analysis of scan results."""
    if not LLM_AVAILABLE:
        return jsonify({"error": "LLM client not available — is llm_client.py present?"}), 503

    data = request.get_json()
    results = data.get("results", [])
    env = data.get("env", "dev")

    if not results:
        return jsonify({"error": "No scan results provided"}), 400

    ready        = [r["app_name"] for r in results if not r.get("in_okta") and not r.get("requires_review") and r.get("acs_count", 0) > 0 and not r.get("parse_error")]
    needs_review = [r["app_name"] for r in results if r.get("requires_review")]
    no_acs       = [r["app_name"] for r in results if r.get("acs_count", 0) == 0 and not r.get("parse_error")]
    cert_gaps    = [{
                        "app_name": r["app_name"],
                        "missing": "signing" if r.get("has_enc_cert") and not r.get("has_signing_cert") else "encryption"
                    } for r in results if bool(r.get("has_enc_cert")) != bool(r.get("has_signing_cert"))]
    acs_mismatch = [{
                        "app_name": r["app_name"],
                        "adfs": r.get("acs_count"),
                        "okta": r.get("okta_acs_count")
                    } for r in results if r.get("in_okta") and r.get("okta_acs_count") is not None and r.get("okta_acs_count") != r.get("acs_count")]
    parse_errors = [r["app_name"] for r in results if r.get("parse_error")]

    sections = {
        "env": env,
        "total": len(results),
        "ready": ready,
        "no_acs": no_acs,
        "cert_gaps": cert_gaps,
        "acs_mismatch": acs_mismatch,
        "parse_errors": parse_errors,
    }

    prompt = (
        "For each ADFS app name below, write exactly one bullet in this format:\n"
        "- AppName: [one sentence — the single most likely SAML migration concern based on the app name]\n\n"
        "Rules: no intro, no conclusion, no generic advice, no extra text. Just the bullets.\n\n"
        "Apps:\n" + "\n".join(f"- {n}" for n in needs_review)
    ) if needs_review else None

    def generate():
        yield f"data: {json.dumps({'type': 'sections', 'data': sections})}\n\n"
        if prompt and LLM_AVAILABLE:
            try:
                for chunk in llm_ask_stream(prompt, model="fast"):
                    yield f"data: {json.dumps({'type': 'chunk', 'text': chunk})}\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'type': 'error', 'msg': str(e)})}\n\n"
        yield f"data: {json.dumps({'type': 'done'})}\n\n"

    return Response(
        stream_with_context(generate()),
        content_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ---------------------------------------------------------------------------
# Log browser routes — KQL against ADFSImportRuns_CL when LA enabled,
# legacy JSON-file path otherwise.
# ---------------------------------------------------------------------------

def _query_la(kql: str, days: int = 365) -> list[dict]:
    """Run a KQL query against the LA workspace via the Monitor Query SDK
    using the Container App's managed identity. Returns a list of row dicts."""
    from azure.identity import DefaultAzureCredential
    from azure.monitor.query import LogsQueryClient
    from datetime import timedelta

    cred = DefaultAzureCredential()
    client = LogsQueryClient(cred)
    resp = client.query_resource(
        resource_id=LA_RESOURCE_ID,
        query=kql,
        timespan=timedelta(days=days),
    )
    rows = []
    for tbl in resp.tables:
        cols = [c for c in tbl.columns]
        for r in tbl.rows:
            rows.append(dict(zip(cols, r)))
    return rows


@app.route("/logs")
def logs_page():
    return render_template("logs.html", version=APP_VERSION)


@app.route("/api/logs")
def api_logs_list():
    """Run summaries — newest first."""
    if LA_QUERY_ENABLED:
        try:
            kql = (
                f"{LA_TABLE_NAME}_CL "
                "| where kind_s == 'summary' "
                "| project ts_t, run_id_s, env_s, "
                "  apps_requested_s, "
                "  summary_created_d, summary_skipped_d, summary_error_d, "
                "  input_dir_s "
                "| order by ts_t desc "
                "| take 200"
            )
            rows = _query_la(kql)
            out = []
            for r in rows:
                out.append({
                    "filename":  r.get("run_id_s") or "",
                    "timestamp": (r.get("ts_t").isoformat() if r.get("ts_t") else ""),
                    "env":       r.get("env_s") or "",
                    "summary":   {
                        "created": int(r.get("summary_created_d") or 0),
                        "skipped": int(r.get("summary_skipped_d") or 0),
                        "error":   int(r.get("summary_error_d") or 0),
                    },
                    "app_count": len((r.get("apps_requested_s") or "").split(",")) if r.get("apps_requested_s") else 0,
                })
            return jsonify(out)
        except Exception as e:
            log.exception("LA query failed; returning empty list")
            return jsonify({"error": str(e)}), 502

    # Local-dev fallback: legacy JSON files
    files = []
    for f in sorted(LOG_DIR.glob("*.json"), reverse=True):
        try:
            data = json.loads(f.read_text())
            files.append({
                "filename": f.name,
                "timestamp": data.get("timestamp", ""),
                "env": data.get("env", ""),
                "summary": data.get("summary", {}),
                "app_count": len(data.get("apps_requested", [])),
            })
        except Exception:
            pass
    return jsonify(files)


@app.route("/api/logs/<run_id>")
def api_logs_get(run_id):
    """Full event detail for one run."""
    if LA_QUERY_ENABLED:
        try:
            # Fetch all events + summary for this run
            kql = (
                f"{LA_TABLE_NAME}_CL "
                f"| where run_id_s == '{run_id}' "
                "| project ts_t, kind_s, evt_s, level_s, msg_s, app_s, status_s, "
                "  okta_id_s, env_s, input_dir_s, apps_requested_s, "
                "  summary_created_d, summary_skipped_d, summary_error_d "
                "| order by ts_t asc"
            )
            rows = _query_la(kql)
            events = []
            summary = None
            env = ""
            timestamp = ""
            input_dir = ""
            apps_requested: list[str] = []
            for r in rows:
                env = r.get("env_s") or env
                if r.get("kind_s") == "summary":
                    summary = {
                        "created": int(r.get("summary_created_d") or 0),
                        "skipped": int(r.get("summary_skipped_d") or 0),
                        "error":   int(r.get("summary_error_d") or 0),
                    }
                    timestamp = r.get("ts_t").isoformat() if r.get("ts_t") else ""
                    input_dir = r.get("input_dir_s") or ""
                    apps_requested = [a for a in (r.get("apps_requested_s") or "").split(",") if a]
                else:
                    evt = {"type": r.get("evt_s") or ""}
                    for k_dst, k_src in [
                        ("level", "level_s"), ("msg", "msg_s"), ("app", "app_s"),
                        ("status", "status_s"), ("okta_id", "okta_id_s"),
                    ]:
                        if r.get(k_src):
                            evt[k_dst] = r[k_src]
                    events.append(evt)
            if not events and summary is None:
                return jsonify({"error": "Not found"}), 404
            return jsonify({
                "run_id":         run_id,
                "timestamp":      timestamp,
                "env":            env,
                "input_dir":      input_dir,
                "apps_requested": apps_requested,
                "summary":        summary or {},
                "events":         events,
            })
        except Exception as e:
            log.exception("LA query failed")
            return jsonify({"error": str(e)}), 502

    # Local-dev fallback: legacy JSON file by filename
    path = (LOG_DIR / run_id).resolve()
    if not str(path).startswith(str(LOG_DIR.resolve())):
        return jsonify({"error": "Invalid filename"}), 400
    if not path.exists():
        return jsonify({"error": "Not found"}), 404
    try:
        return jsonify(json.loads(path.read_text()))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    print(f"\n  ADFS → Okta Migration v{APP_VERSION}")
    print(f"  Open: http://localhost:{port}\n")
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
