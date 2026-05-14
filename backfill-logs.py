#!/usr/bin/env python3
"""
backfill-logs.py — One-time replay of legacy logs/import_*.json files into the
Azure Log Analytics workspace, where the live tool now ships its records. Each
historical run becomes one summary record + N event records in the same custom
table the live tool writes to (LA_TABLE_NAME, default ADFSImportRuns).

Usage:
  LA_WORKSPACE_ID=<customerId> LA_WORKSPACE_KEY=<sharedKey> \\
    LA_TABLE_NAME=ADFSImportRuns \\
    python3 backfill-logs.py [logs_dir]

logs_dir defaults to ./logs.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests


def la_signature(workspace_id, shared_key, date, content_length, method, content_type, resource):
    string_to_hash = (f"{method}\n{content_length}\n{content_type}\n"
                      f"x-ms-date:{date}\n{resource}")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, string_to_hash.encode("utf-8"), hashlib.sha256).digest()
    ).decode("utf-8")
    return f"SharedKey {workspace_id}:{encoded_hash}"


def la_post(workspace_id, shared_key, log_type, records):
    body = json.dumps(records).encode("utf-8")
    rfc_date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    sig = la_signature(workspace_id, shared_key, rfc_date, len(body),
                       "POST", "application/json", "/api/logs")
    url = f"https://host.example.gov}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
    r = requests.post(url, data=body, headers={
        "Content-Type":   "application/json",
        "Authorization":  sig,
        "Log-Type":       log_type,
        "x-ms-date":      rfc_date,
        "time-generated-field": "ts",
    }, timeout=30)
    if r.status_code >= 300:
        raise RuntimeError(f"LA POST failed {r.status_code}: {r.text[:200]}")


def main():
    ws_id = os.environ.get("LA_WORKSPACE_ID", "").strip()
    ws_key = os.environ.get("LA_WORKSPACE_KEY", "").strip()
    log_type = os.environ.get("LA_TABLE_NAME", "ADFSImportRuns").strip()
    if not ws_id or not ws_key:
        print("ERROR: LA_WORKSPACE_ID and LA_WORKSPACE_KEY required.", file=sys.stderr)
        return 2

    logs_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("logs")
    if not logs_dir.is_dir():
        print(f"ERROR: {logs_dir} not found.", file=sys.stderr)
        return 2

    files = sorted(logs_dir.glob("import_*.json"))
    print(f"Backfilling {len(files)} historical run(s) → {log_type}_CL...")

    for f in files:
        try:
            data = json.loads(f.read_text())
        except Exception as e:
            print(f"  SKIP {f.name}: parse error ({e})")
            continue

        run_id = data.get("run_id") or uuid.uuid4().hex
        env = data.get("env", "")
        ts = data.get("timestamp", datetime.now(timezone.utc).isoformat(timespec="seconds"))
        apps_requested = data.get("apps_requested") or []
        events = data.get("events") or []
        summary = data.get("summary") or {}

        records = []
        # Summary record
        records.append({
            "ts":      ts,
            "env":     env,
            "run_id":  run_id,
            "kind":    "summary",
            "input_dir":      data.get("input_dir", ""),
            "apps_requested": ",".join(apps_requested),
            "summary_created": int(summary.get("created", 0)),
            "summary_skipped": int(summary.get("skipped", 0)),
            "summary_error":   int(summary.get("error", 0)),
            "backfilled":      True,
            "backfill_source": f.name,
        })
        # Event records
        for ev in events:
            rec = {
                "ts":      ts,    # legacy events lack per-event timestamps
                "env":     env,
                "run_id":  run_id,
                "kind":    "event",
                "evt":     ev.get("type", ""),
                "backfilled": True,
                "backfill_source": f.name,
            }
            for k in ("level", "msg", "app", "status", "okta_id"):
                if ev.get(k) is not None:
                    rec[k] = ev[k]
            records.append(rec)

        try:
            # POST in chunks of 500 to stay well under the 30 MB body limit.
            CHUNK = 500
            for i in range(0, len(records), CHUNK):
                la_post(ws_id, ws_key, log_type, records[i:i + CHUNK])
            print(f"  OK   {f.name}  run_id={run_id[:8]}…  records={len(records)}")
        except Exception as e:
            print(f"  FAIL {f.name}: {e}")

    print("Done. Note: LA ingestion may take a few minutes to surface in queries.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
