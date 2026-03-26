"""
app.py — ADFS → Okta Migration Tool (local Flask UI)
Run: .venv/bin/python app.py
Then open: http://localhost:5001
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import requests as req_lib
from dotenv import load_dotenv
from flask import Flask, Response, jsonify, render_template, request, stream_with_context

try:
    import keyring as _keyring
    KEYRING_SERVICE = "adfs-okta-migration"
except ImportError:
    _keyring = None  # type: ignore
    KEYRING_SERVICE = ""


def get_token(var_name: str) -> str:
    """Read a token from OS keyring first, fall back to .env / environment variable."""
    if _keyring:
        val = _keyring.get_password(KEYRING_SERVICE, var_name)
        if val:
            return val.strip()
    return os.environ.get(var_name, "").strip()


# Load .env from the project folder
load_dotenv(Path(__file__).parent / ".env")

# Import core logic from the CLI script
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

APP_VERSION = "1.7.0"

app = Flask(__name__)

LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/api/browse")
def api_browse():
    """Show a native macOS folder picker and return the chosen path."""
    script = 'POSIX path of (choose folder with prompt "Select ADFS export folder:")'
    try:
        result = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True, text=True, timeout=60
        )
        path = result.stdout.strip().rstrip("/")
        if path:
            return jsonify({"path": path})
        return jsonify({"path": ""}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/")
def index():
    default_dir = os.environ.get("ADFS_EXPORT_DIR", "")
    return render_template("index.html", default_dir=default_dir, version=APP_VERSION)


@app.route("/api/policies")
def api_policies():
    """Return available ACCESS_POLICY policies for the given env."""
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


@app.route("/api/scan")
def api_scan():
    """Scan an ADFS export folder and cross-reference against Okta."""
    env = request.args.get("env", "dev")
    input_dir = request.args.get("input_dir", "").strip()

    if not input_dir:
        return jsonify({"error": "input_dir is required"}), 400
    root = Path(input_dir)
    if not root.is_dir():
        return jsonify({"error": f"Directory not found: {input_dir}"}), 400
    if env not in OKTA_ADMIN_ENVIRONMENTS:
        return jsonify({"error": f"Unknown environment: {env}"}), 400

    env_cfg = OKTA_ADMIN_ENVIRONMENTS[env]
    token = get_token(env_cfg["token_var"])
    if not token:
        return jsonify({"error": f"{env_cfg['token_var']} is not set"}), 400

    client = OktaClient(env_cfg["url"], token)

    try:
        okta_apps = client.get_all_apps()  # label → app dict, single paginated fetch
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
        okta_status = existing.get("status") if existing else None  # "ACTIVE" | "INACTIVE"
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


@app.route("/api/routing-rules")
def api_routing_rules():
    """Return available IDP routing rules for the given env."""
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


@app.route("/api/toggle-status", methods=["POST"])
def api_toggle_status():
    """Activate or deactivate an Okta app."""
    data = request.get_json()
    env = data.get("env", "dev")
    app_id = data.get("app_id", "").strip()
    action = data.get("action", "")  # "activate" | "deactivate"

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
    folder_names = data.get("apps", [])
    policy_id = data.get("policy_id", "").strip()
    routing_rule_id = data.get("routing_rule_id", "").strip()
    routing_policy_id = data.get("routing_policy_id", "").strip()
    update_existing = bool(data.get("update_existing", False))

    if env not in OKTA_ADMIN_ENVIRONMENTS:
        return jsonify({"error": f"Unknown environment: {env}"}), 400

    env_cfg = OKTA_ADMIN_ENVIRONMENTS[env]
    token = get_token(env_cfg["token_var"])
    root = Path(input_dir)

    run_ts = datetime.now()

    def generate():
        log_events = []

        def emit(evt_type, **kwargs):
            payload = {"type": evt_type, **kwargs}
            log_events.append(payload)
            return f"data: {json.dumps(payload)}\n\n"

        def save_log(summary):
            ts_str = run_ts.strftime("%Y-%m-%d_%H-%M-%S")
            filename = f"import_{env}_{ts_str}.json"
            record = {
                "timestamp": run_ts.isoformat(timespec="seconds"),
                "env": env,
                "input_dir": input_dir,
                "apps_requested": folder_names,
                "summary": summary,
                "events": log_events,
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

                # Update mode — apply policy and group assignments to existing app
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

            # Encryption cert (signing cert skipped — requires SLO)
            enc_cert = load_cert(folder, cfg.get("encryption_cert_file"))
            if enc_cert:
                yield emit("log", level="info", msg=f"  Encryption cert: {cfg['encryption_cert_file']}")

            # Group assignments
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

            # Create
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

            # Assign authentication policy
            if policy_id:
                try:
                    client.assign_policy_to_app(okta_id, policy_id)
                    yield emit("log", level="info", msg=f"  Auth policy assigned")
                except req_lib.HTTPError as e:
                    body = e.response.text if e.response is not None else str(e)
                    yield emit("log", level="warn", msg=f"  Error assigning policy: {body}")

            # Assign IDP routing rule
            if routing_rule_id and routing_policy_id:
                try:
                    client.add_app_to_routing_rule(routing_policy_id, routing_rule_id, okta_id)
                    yield emit("log", level="info", msg=f"  IDP routing rule assigned")
                except req_lib.HTTPError as e:
                    body = e.response.text if e.response is not None else str(e)
                    yield emit("log", level="warn", msg=f"  Error assigning routing rule: {body}")

            # Assign groups
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

    # Python computes all sections — LLM only writes one sentence per flagged app
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

    # Emit structured Python data immediately, then stream LLM for section 2 only
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
        # Emit Python-computed sections instantly
        yield f"data: {json.dumps({'type': 'sections', 'data': sections})}\n\n"

        # Stream LLM only for needs_review explanations
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
# Log browser routes
# ---------------------------------------------------------------------------

@app.route("/logs")
def logs_page():
    return render_template("logs.html", version=APP_VERSION)


@app.route("/api/logs")
def api_logs_list():
    """Return metadata for all saved import log files, newest first."""
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


@app.route("/api/logs/<filename>")
def api_logs_get(filename):
    """Return the full content of a single log file."""
    # Prevent path traversal
    path = (LOG_DIR / filename).resolve()
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
    print(f"\n  ADFS → Okta Migration Tool v{APP_VERSION}")
    print(f"  Open: http://localhost:{port}\n")
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
