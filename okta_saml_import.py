#!/usr/bin/env python3
"""
okta_saml_import.py
====================
Reads ADFS export folders produced by Export-ADFSRelyingPartyTrusts_v5.ps1
and creates Okta SAML 2.0 apps via the Okta Apps API.

Usage:
  python okta_saml_import.py --input-dir /path/to/ADFS_Migration_PROD_20260311_120000
  python okta_saml_import.py --input-dir /path/to/... --dry-run
  python okta_saml_import.py --input-dir /path/to/... --app "UCC-Cisco-internal-host"

Environment variables (or .env file):
  OKTA_ORG_URL      e.g. https://your-org.okta.com
  OKTA_API_TOKEN    Okta API token with app create + cert upload permissions

Options:
  --env dev|stg|prod  Target Okta environment (default: dev)
  --input-dir DIR     Root ADFS export folder (required)
  --app NAME          Process only one app by folder/app name (optional)
  --dry-run           Preview actions, no API calls
  --skip-certs        Skip certificate upload even if PEM files exist
  --log-dir DIR       Directory for log files (default: logs/ next to script)
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import re
import sys
from datetime import datetime
from pathlib import Path

import requests
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Environment config — mirrors OKTA_ENVIRONMENTS pattern from sso_tester_logic.py
# ---------------------------------------------------------------------------

OKTA_ADMIN_ENVIRONMENTS = {
    "dev":  {"url": "https://dev-your-org.okta.com",     "token_var": "OKTA_DEV_API_TOKEN"},
    "stg":  {"url": "https://staging-your-org.okta.com", "token_var": "OKTA_STG_API_TOKEN"},
    "prod": {"url": "https://your-org.okta.com",         "token_var": "OKTA_PROD_API_TOKEN"},
}

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def setup_logging(log_dir: Path) -> logging.Logger:
    log_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"okta_import_{ts}.log"

    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    logging.basicConfig(
        level=logging.INFO,
        format=fmt,
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout),
        ],
    )
    log = logging.getLogger("okta_import")
    log.info("Log file: %s", log_file)
    return log


# ---------------------------------------------------------------------------
# Config file parser
# ---------------------------------------------------------------------------

def parse_config(config_path: Path) -> dict:
    """Parse an ADFS export _config.txt file into a dict."""
    text = config_path.read_text(encoding="utf-8-sig")  # utf-8-sig strips BOM
    data = {
        "app_name": "",
        "sso_url": "",
        "entity_id": "",
        "name_id_format": "unspecified",
        "requires_review": False,
        "signing_cert_file": None,
        "encryption_cert_file": None,
        "acs_endpoints": [],   # list of URL strings, in index order
        "attribute_statements": [],
        "access_policy": "",
        "enabled": True,
    }

    # Simple key: value lines
    kv_patterns = {
        "app_name":           r"^App Name:\s*(.+)",
        "sso_url":            r"^SSO URL:\s*(.+)",
        "entity_id":          r"^Entity ID:\s*(.+)",
        "name_id_format":     r"^Name ID Format:\s*(.+)",
        "requires_review":    r"^RequiresReview:\s*(TRUE|FALSE)",
        "signing_cert_file":  r"^Signing Certificate:\s*(.+)",
        "encryption_cert_file": r"^Encryption Certificate:\s*(.+)",
        "access_policy":      r"^Access Control Policy:\s*(.+)",
    }

    for line in text.splitlines():
        line = line.strip()
        for key, pattern in kv_patterns.items():
            m = re.match(pattern, line, re.IGNORECASE)
            if m:
                val = m.group(1).strip()
                if key == "requires_review":
                    data[key] = val.upper() == "TRUE"
                elif val.lower() == "none":
                    data[key] = None
                else:
                    data[key] = val

    # Parse ACS endpoint lines: "  [N] https://..."
    for m in re.finditer(r"^\s*\[(\d+)\]\s+(https?://\S+)", text, re.MULTILINE):
        idx = int(m.group(1))
        url = m.group(2).strip()
        # Expand list if needed
        while len(data["acs_endpoints"]) <= idx:
            data["acs_endpoints"].append(None)
        data["acs_endpoints"][idx] = url

    # Remove any None gaps (shouldn't happen but safety)
    data["acs_endpoints"] = [u for u in data["acs_endpoints"] if u]

    # Parse attribute statements (lines after "Attribute Statements:")
    in_attrs = False
    for line in text.splitlines():
        if re.match(r"^Attribute Statements:", line):
            in_attrs = True
            continue
        if in_attrs:
            if line.strip() == "" or re.match(r"^(Access Control|Raw Issuance|Notes:|Enabled:)", line.strip()):
                in_attrs = False
                continue
            stripped = line.strip()
            if stripped:
                data["attribute_statements"].append(stripped)

    # Parse group assignments from "Okta Translation Notes:" section.
    # Two possible lines we act on:
    #   "- Create assignment rule for all users"        → assign Everyone
    #   "- Create assignment rule for group: "Name""   → assign that Okta group
    # Lines starting with "- MFA group documented" are informational only — skip.
    data["assign_everyone"] = False
    data["assign_groups"] = []   # list of Okta group name strings (domain prefix stripped)

    in_notes = False
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r"^Okta Translation Notes:", stripped):
            in_notes = True
            continue
        if in_notes:
            # Stop at the next blank section header or end of Access Control block
            if stripped and not stripped.startswith("-"):
                in_notes = False
                continue
            if re.search(r"create assignment rule for all users", stripped, re.IGNORECASE):
                data["assign_everyone"] = True
            elif m := re.search(r'create assignment rule for group[:\s]+"([^"]+)"', stripped, re.IGNORECASE):
                # Strip DOMAIN\ prefix (e.g. "SENATEGOV\MyGroup" → "MyGroup")
                group_name = re.sub(r"^[^\\]+\\", "", m.group(1)).strip()
                if group_name and group_name not in data["assign_groups"]:
                    data["assign_groups"].append(group_name)

    # Fallback: if no assignment was parsed at all, default to Everyone
    if not data["assign_everyone"] and not data["assign_groups"]:
        data["assign_everyone"] = True

    return data


# ---------------------------------------------------------------------------
# Okta API helpers
# ---------------------------------------------------------------------------

class OktaClient:
    def __init__(self, org_url: str, token: str, dry_run: bool = False):
        self.base = org_url.rstrip("/")
        self.headers = {
            "Authorization": f"SSWS {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self.dry_run = dry_run
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def _wait_for_rate_limit(self, resp) -> None:
        """Sleep until Okta's rate limit window resets."""
        import time
        reset_ts = resp.headers.get("X-Rate-Limit-Reset")
        if reset_ts:
            wait = max(1, int(reset_ts) - int(time.time()) + 1)
        else:
            wait = 10
        time.sleep(wait)

    def _get(self, path: str) -> dict | list:
        for _ in range(4):
            resp = self.session.get(f"{self.base}{path}")
            if resp.status_code == 429:
                self._wait_for_rate_limit(resp)
                continue
            resp.raise_for_status()
            return resp.json()
        resp.raise_for_status()

    def _post(self, path: str, body: dict, debug: bool = False) -> dict:
        if self.dry_run:
            return {"id": "DRY_RUN", "_dryrun": True}
        if debug:
            import sys
            print("\n--- DEBUG: POST body ---", file=sys.stderr)
            print(json.dumps(body, indent=2), file=sys.stderr)
            print("--- END DEBUG ---\n", file=sys.stderr)
        for _ in range(4):
            resp = self.session.post(f"{self.base}{path}", json=body)
            if resp.status_code == 429:
                self._wait_for_rate_limit(resp)
                continue
            resp.raise_for_status()
            return resp.json()
        resp.raise_for_status()

    def _put(self, path: str, body: dict) -> dict:
        if self.dry_run:
            return {"id": "DRY_RUN", "_dryrun": True}
        for _ in range(4):
            resp = self.session.put(f"{self.base}{path}", json=body)
            if resp.status_code == 429:
                self._wait_for_rate_limit(resp)
                continue
            resp.raise_for_status()
            return resp.json()
        resp.raise_for_status()

    def get_all_apps(self) -> dict[str, dict]:
        """Fetch all apps from Okta (paginated) and return a label→app dict."""
        url = f"{self.base}/api/v1/apps?limit=200"
        apps_by_label: dict[str, dict] = {}
        while url:
            resp = self.session.get(url)
            resp.raise_for_status()
            for app in resp.json():
                apps_by_label[app["label"]] = app
            # Follow Okta's Link: <url>; rel="next" header for pagination
            next_link = None
            for part in resp.headers.get("Link", "").split(","):
                part = part.strip()
                if 'rel="next"' in part:
                    next_link = part.split(";")[0].strip().strip("<>")
            url = next_link
        return apps_by_label

    def find_app_by_label(self, label: str) -> dict | None:
        """Return first existing app whose label matches exactly."""
        encoded = requests.utils.quote(label)
        results = self._get(f"/api/v1/apps?q={encoded}&limit=10")
        for app in results:
            if app.get("label") == label:
                return app
        return None

    def find_group_by_name(self, name: str) -> dict | None:
        """Return first Okta group whose profile.name matches exactly."""
        encoded = requests.utils.quote(name)
        results = self._get(f"/api/v1/groups?q={encoded}&limit=10")
        for grp in results:
            if grp.get("profile", {}).get("name") == name:
                return grp
        return None

    def assign_group_to_app(self, app_id: str, group_id: str) -> None:
        """Assign an Okta group to an app (PUT /api/v1/apps/{id}/groups/{gid})."""
        if self.dry_run:
            return
        resp = self.session.put(f"{self.base}/api/v1/apps/{app_id}/groups/{group_id}", json={})
        resp.raise_for_status()

    def activate_app(self, app_id: str) -> None:
        if self.dry_run:
            return
        resp = self.session.post(f"{self.base}/api/v1/apps/{app_id}/lifecycle/activate")
        resp.raise_for_status()

    def deactivate_app(self, app_id: str) -> None:
        if self.dry_run:
            return
        resp = self.session.post(f"{self.base}/api/v1/apps/{app_id}/lifecycle/deactivate")
        resp.raise_for_status()

    def assign_policy_to_app(self, app_id: str, policy_id: str) -> None:
        """Assign an authentication policy to an app (PUT /api/v1/apps/{id}/policies/{pid})."""
        if self.dry_run:
            return
        resp = self.session.put(f"{self.base}/api/v1/apps/{app_id}/policies/{policy_id}")
        resp.raise_for_status()

    def list_access_policies(self) -> list[dict]:
        """Return all ACCESS_POLICY policies as [{id, name}]."""
        data = self._get("/api/v1/policies?type=ACCESS_POLICY&limit=200")
        return [{"id": p["id"], "name": p["name"]} for p in data]

    def get_app_policy_map(self) -> dict[str, str]:
        """Return {app_id: policy_name} by reverse-scanning all ACCESS_POLICY policies."""
        policies = self._get("/api/v1/policies?type=ACCESS_POLICY&limit=200")
        result = {}
        for policy in policies:
            try:
                apps = self._get(f"/api/v1/policies/{policy['id']}/app?limit=500")
                for app in apps:
                    result[app["id"]] = policy["name"]
            except Exception:
                pass
        return result

    def get_app_routing_rule_map(self) -> dict[str, str]:
        """Return {app_id: rule_name} by scanning IDP_DISCOVERY policy rules."""
        policies = self._get("/api/v1/policies?type=IDP_DISCOVERY&limit=200")
        result = {}
        for policy in policies:
            try:
                rules = self._get(f"/api/v1/policies/{policy['id']}/rules")
                for rule in rules:
                    for item in rule.get("conditions", {}).get("app", {}).get("include", []):
                        if item.get("type") == "APP" and item.get("id"):
                            result[item["id"]] = rule["name"]
            except Exception:
                pass
        return result

    def list_idp_routing_rules(self) -> list[dict]:
        """Return all IDP routing rules as [{id, name, policy_id}]."""
        policies = self._get("/api/v1/policies?type=IDP_DISCOVERY&limit=200")
        results = []
        for policy in policies:
            rules = self._get(f"/api/v1/policies/{policy['id']}/rules")
            for rule in rules:
                results.append({
                    "id": rule["id"],
                    "name": rule["name"],
                    "policy_id": policy["id"],
                })
        return results

    def add_app_to_routing_rule(self, policy_id: str, rule_id: str, app_id: str) -> None:
        """Add an app to an IDP routing rule's app conditions."""
        if self.dry_run:
            return
        rule = self._get(f"/api/v1/policies/{policy_id}/rules/{rule_id}")
        includes = rule.setdefault("conditions", {}).setdefault("app", {}).setdefault("include", [])
        if app_id not in {item.get("id") for item in includes}:
            includes.append({"type": "APP", "id": app_id})
            resp = self.session.put(
                f"{self.base}/api/v1/policies/{policy_id}/rules/{rule_id}",
                json=rule,
            )
            resp.raise_for_status()

    def create_saml_app(self, cfg: dict, cert_pem: str | None = None, enc_cert_pem: str | None = None, debug: bool = False) -> dict:
        """Build and POST a SAML 2.0 app from parsed config."""
        # Full URN map — Okta requires exact case in the URN string
        name_id_urn_map = {
            "emailaddress":    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "email":           "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "unspecified":     "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
            "persistent":      "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            "transient":       "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
            "x509subjectname": "urn:oasis:names:tc:SAML:1.1:nameid-format:x509SubjectName",
        }
        name_id_format_urn = name_id_urn_map.get(
            cfg["name_id_format"].lower(),
            "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
        )

        # Primary ACS URL (index 0)
        primary_acs = cfg["acs_endpoints"][0] if cfg["acs_endpoints"] else cfg["sso_url"]

        # All ACS endpoints for Okta acsEndpoints array
        acs_endpoints = [
            {"url": url, "index": i}
            for i, url in enumerate(cfg["acs_endpoints"])
        ]

        # Build attribute statements — nameFormat is required by Okta
        attribute_statements = []
        for attr_line in cfg["attribute_statements"]:
            if "→" in attr_line or "->" in attr_line:
                parts = re.split(r"→|->", attr_line, maxsplit=1)
                okta_attr_name = parts[0].strip()
                okta_attr_value = parts[1].strip()
                attribute_statements.append({
                    "type": "EXPRESSION",
                    "name": okta_attr_name,
                    "namespace": "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified",
                    "values": [okta_attr_value],
                })

        sign_on_settings = {
            "defaultRelayState": "",
            "ssoAcsUrl": primary_acs,
            "idpIssuer": "http://www.okta.com/${org.externalKey}",
            "audience": cfg["entity_id"],
            "recipient": primary_acs,
            "destination": primary_acs,
            "subjectNameIdTemplate": "${user.userName}",
            "subjectNameIdFormat": name_id_format_urn,
            "responseSigned": True,
            "assertionSigned": True,
            "signatureAlgorithm": "RSA_SHA256",
            "digestAlgorithm": "SHA256",
            "honorForceAuthn": True,
            "authnContextClassRef": "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
            "requestCompressed": False,
            "attributeStatements": attribute_statements,
        }

        # SP signing cert — requires requestSigned:true so Okta accepts the certificate
        if cert_pem:
            cert_b64 = re.sub(r"-----[^-]+-----|\s", "", cert_pem)
            sign_on_settings["requestSigned"] = True
            sign_on_settings["spCertificate"] = {"x5c": [cert_b64]}

        body = {
            "label": cfg["app_name"],
            "status": "ACTIVE",
            "signOnMode": "SAML_2_0",
            "visibility": {
                "autoSubmitToolbar": False,
                "hide": {"iOS": False, "web": False},
            },
            "settings": {
                "signOn": sign_on_settings,
            },
        }

        # Step 1: Create the app (Okta ignores acsEndpoints on initial POST)
        result = self._post("/api/v1/apps", body, debug=debug)

        # Step 2: PUT to apply acsEndpoints and/or encryption cert.
        # Okta ignores acsEndpoints on initial POST; encryption cert also requires a PUT.
        needs_put = (len(acs_endpoints) > 1 or enc_cert_pem) and not self.dry_run
        if needs_put:
            app_id = result["id"]
            current = self._get(f"/api/v1/apps/{app_id}")
            if len(acs_endpoints) > 1:
                current["settings"]["signOn"]["allowMultipleAcsEndpoints"] = True
                current["settings"]["signOn"]["acsEndpoints"] = acs_endpoints
            if enc_cert_pem:
                enc_b64 = re.sub(r"-----[^-]+-----|\s", "", enc_cert_pem)
                current["settings"]["signOn"]["assertionEncryption"] = {
                    "enabled": True,
                    "encryptionAlgorithm": "AES256_GCM",
                    "keyTransportAlgorithm": "RSA_OAEP",
                    "x5c": [enc_b64],
                }
            result = self._put(f"/api/v1/apps/{app_id}", current)

        return result


# ---------------------------------------------------------------------------
# Main import logic
# ---------------------------------------------------------------------------

def load_cert(folder: Path, cert_file: str | None) -> str | None:
    if not cert_file:
        return None
    cert_path = folder / cert_file
    if cert_path.exists():
        return cert_path.read_text(encoding="ascii")
    return None


def import_app(folder: Path, client: OktaClient, skip_certs: bool, skip_signing_cert: bool, log: logging.Logger, debug: bool = False, max_acs: int = 0) -> str:
    """Import one app folder. Returns 'created', 'skipped', or 'error'."""
    config_files = list(folder.glob("*_config.txt"))
    if not config_files:
        log.warning("No _config.txt found in %s — skipping", folder.name)
        return "skipped"

    config_path = config_files[0]
    try:
        cfg = parse_config(config_path)
    except Exception as e:
        log.error("Failed to parse %s: %s", config_path, e)
        return "error"

    if max_acs and len(cfg["acs_endpoints"]) > max_acs:
        cfg["acs_endpoints"] = cfg["acs_endpoints"][:max_acs]
        log.info("  [DEBUG] Limiting to %d ACS endpoints", max_acs)

    app_name = cfg["app_name"] or folder.name
    log.info("--- Processing: %s (%d ACS endpoints)", app_name, len(cfg["acs_endpoints"]))

    if cfg["requires_review"]:
        log.warning("  [REVIEW FLAG] %s is flagged RequiresReview=TRUE — importing anyway", app_name)

    # Idempotency: check if app already exists
    existing = client.find_app_by_label(app_name)
    if existing:
        log.info("  SKIP: App '%s' already exists in Okta (id=%s)", app_name, existing.get("id"))
        return "skipped"

    # Load certs
    # Signing cert requires SLO to be configured in Okta — skipped by default via --skip-signing-cert.
    # Encryption cert is safe to apply automatically.
    signing_cert = None
    encryption_cert = None
    if not skip_certs:
        if not skip_signing_cert:
            signing_cert = load_cert(folder, cfg.get("signing_cert_file"))
            if signing_cert:
                log.info("  Found signing cert: %s", cfg["signing_cert_file"])
        encryption_cert = load_cert(folder, cfg.get("encryption_cert_file"))
        if encryption_cert:
            log.info("  Found encryption cert: %s", cfg["encryption_cert_file"])

    # Resolve group assignments from parsed config
    groups_to_assign = []  # list of (label, id) tuples

    if cfg["assign_everyone"]:
        log.info("  Assignment: Everyone (all users)")
        if not client.dry_run:
            grp = client.find_group_by_name("Everyone")
            if grp:
                groups_to_assign.append(("Everyone", grp["id"]))
            else:
                log.warning("  Could not find 'Everyone' group in Okta — skipping assignment")
        else:
            groups_to_assign.append(("Everyone", "DRY_RUN_ID"))

    for group_name in cfg["assign_groups"]:
        log.info("  Assignment: group '%s'", group_name)
        if not client.dry_run:
            grp = client.find_group_by_name(group_name)
            if grp:
                groups_to_assign.append((group_name, grp["id"]))
            else:
                log.warning("  Group '%s' not found in Okta — skipping assignment", group_name)
        else:
            groups_to_assign.append((group_name, "DRY_RUN_ID"))

    # Create the app
    log.info("  Creating SAML app '%s'...", app_name)
    if client.dry_run:
        log.info("  [DRY RUN] Would POST /api/v1/apps for '%s'", app_name)
        log.info("  [DRY RUN] ACS endpoints: %s", cfg["acs_endpoints"][:3])
        if len(cfg["acs_endpoints"]) > 3:
            log.info("  [DRY RUN]   ... and %d more", len(cfg["acs_endpoints"]) - 3)
        for label, _ in groups_to_assign:
            log.info("  [DRY RUN] Would assign group: '%s'", label)
        return "dry_run"

    try:
        result = client.create_saml_app(cfg, cert_pem=signing_cert, enc_cert_pem=encryption_cert, debug=debug)
        app_id = result.get("id")
        log.info("  CREATED: '%s' → Okta app id=%s", app_name, app_id)
    except requests.HTTPError as e:
        log.error("  ERROR creating '%s': %s", app_name, e.response.text if e.response is not None else str(e))
        return "error"

    # Assign groups
    for label, group_id in groups_to_assign:
        try:
            client.assign_group_to_app(app_id, group_id)
            log.info("  ASSIGNED group '%s' to app '%s'", label, app_name)
        except requests.HTTPError as e:
            log.error("  ERROR assigning group '%s': %s", label, e.response.text if e.response else e)

    return "created"


def main():
    load_dotenv()

    parser = argparse.ArgumentParser(description="Import ADFS RPT configs into Okta as SAML 2.0 apps")
    parser.add_argument("--env", choices=OKTA_ADMIN_ENVIRONMENTS.keys(), default="dev",
                        help="Target Okta environment (default: dev)")
    parser.add_argument("--input-dir", required=True, help="Root ADFS export folder")
    parser.add_argument("--app", help="Process only this app (folder name or app name)")
    parser.add_argument("--dry-run", action="store_true", help="Preview only, no API calls")
    parser.add_argument("--skip-certs", action="store_true", help="Skip all certificate uploads")
    parser.add_argument("--skip-signing-cert", action="store_true", default=True,
                        help="Skip SP signing cert (requires SLO; default: True)")
    parser.add_argument("--max-acs", type=int, default=0, help="Limit ACS endpoints to N (0=all; for debugging)")
    parser.add_argument("--debug", action="store_true", help="Print full JSON request body before each POST")
    parser.add_argument("--log-dir", default=None, help="Log output directory")
    args = parser.parse_args()

    script_dir = Path(__file__).parent
    log_dir = Path(args.log_dir) if args.log_dir else script_dir / "logs"
    log = setup_logging(log_dir)

    # Resolve environment config (mirrors Federated tool's OKTA_ENVIRONMENTS pattern)
    env_cfg = OKTA_ADMIN_ENVIRONMENTS[args.env]
    org_url = env_cfg["url"]
    token_var = env_cfg["token_var"]
    api_token = os.environ.get(token_var, "").strip()

    log.info("Target: %s (%s)", args.env.upper(), org_url)

    if not api_token:
        log.error("%s is not set — add it to your .env file", token_var)
        sys.exit(1)

    if args.dry_run:
        log.info("=== DRY RUN MODE — no API calls will be made ===")

    client = OktaClient(org_url, api_token, dry_run=args.dry_run)
    input_dir = Path(args.input_dir)

    if not input_dir.is_dir():
        log.error("Input directory not found: %s", input_dir)
        sys.exit(1)

    # Find app folders (subdirectories that contain a _config.txt)
    if args.app:
        # Single app mode
        app_folder = input_dir / args.app
        if not app_folder.is_dir():
            # Try to find by partial match
            matches = [d for d in input_dir.iterdir() if d.is_dir() and args.app.lower() in d.name.lower()]
            if not matches:
                log.error("App folder not found for: %s", args.app)
                sys.exit(1)
            app_folder = matches[0]
        folders = [app_folder]
    else:
        folders = sorted([d for d in input_dir.iterdir() if d.is_dir()])

    log.info("Found %d app folder(s) to process in: %s", len(folders), input_dir)

    counts = {"created": 0, "skipped": 0, "error": 0, "dry_run": 0}
    for folder in folders:
        result = import_app(folder, client, args.skip_certs, args.skip_signing_cert, log, debug=args.debug, max_acs=args.max_acs)
        counts[result] = counts.get(result, 0) + 1

    log.info("")
    log.info("=== SUMMARY ===")
    log.info("  Created:  %d", counts.get("created", 0))
    log.info("  Skipped:  %d", counts.get("skipped", 0))
    log.info("  Errors:   %d", counts.get("error", 0))
    if args.dry_run:
        log.info("  Dry-run:  %d (would be created)", counts.get("dry_run", 0))


if __name__ == "__main__":
    main()
