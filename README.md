# ADFS → Okta Migration Tool

**v1.7.0 — Production**

---

## The Problem

No tool existed to migrate 200+ enterprise applications from ADFS (Relying Party Trusts) to Okta SAML 2.0 at scale. Manual migration per-app was error-prone and didn't scale.

Specific challenges this tool was built to solve:

- ADFS exports (PowerShell XML) needed parsing into Okta API payloads
- Multi-ACS endpoint apps required special handling — Okta's API has an undocumented POST→PUT two-step behavior for ACS endpoint persistence
- FIPS-compliant encryption certificate upload (AES256_GCM + RSA_OAEP) for GovCloud environments
- Re-running against the same export without creating duplicates (idempotency)
- Group assignment driven by "Okta Translation Notes" embedded in ADFS config
- No visibility into what succeeded or failed without running blind

---

## What It Does

- Parses ADFS Relying Party Trust XML exports generated via PowerShell
- Creates Okta SAML 2.0 apps via API with full configuration: ACS endpoints, Entity ID, name format, encryption certificates, attribute mappings
- Handles multi-ACS endpoint batches with the POST→PUT two-step workaround
- Idempotency checks — skips apps that already exist, no duplicates on re-runs
- Dry-run mode — preview what would be created without touching Okta
- Group assignment from translation notes embedded in ADFS config
- Multi-environment support: DEV / STG / PROD with separate API tokens
- Secure token storage via OS Keyring — no credentials on disk
- Real-time streaming import progress via Server-Sent Events (SSE)
- Import log history with per-run JSON storage and `/logs` page
- **v1.7.0**: Local LLM scan layer — Qwen 2.5 72B via Ollama analyzes import output and flags configuration anomalies before they reach production

---

## Why It's Built This Way

**Local LLM only** — Configuration analysis uses a local Qwen 2.5 72B model via Ollama. No data is sent to cloud APIs. Required in a federal environment where application metadata is sensitive.

**OS Keyring** — All API tokens are stored in the platform keyring (macOS/Windows/Linux). Nothing is written to disk or environment files.

**Idempotency first** — Re-running the tool against the same ADFS export is safe. Existing apps are detected and skipped automatically.

**Dry-run default** — Destructive operations require explicit confirmation before anything touches Okta.

---

## Tech Stack

- Python 3.11+ / Flask (port 5001)
- Okta REST API
- Local LLM: Ollama + Qwen 2.5 72B (see [Related](#related))
- macOS Keyring / OS Keyring (cross-platform)
- Server-Sent Events (SSE) for streaming import progress

---

## Setup

**Requirements:** Python 3.11+, Ollama (optional — required only for AI scan layer)

```bash
pip install -r requirements.txt
```

Configure API tokens (stored in OS keyring — not on disk):

```bash
python setup_tokens.py
```

Run the app:

```bash
python app.py
```

Open: [http://localhost:5001](http://localhost:5001)

---

## Environment Variables

Reference `.env.example` for required configuration. All secrets must be stored via `setup_tokens.py`. Do not put real tokens in `.env`.

---

## Status

Production — actively used for enterprise ADFS → Okta migration at the U.S. Senate.

**v1.7.0 impact:**

- Successfully processed 92 ACS endpoints in a production federal environment
- Resolved critical Okta API behavior: POST→PUT two-step required for ACS endpoint persistence
- Resolved E0000003 error caused by `nameFormat` → `namespace` attribute mapping mismatch
- AI scan layer catches configuration anomalies before they reach production

---

## Related

- **identity-llm-client** — Local LLM client powering the AI scan layer (Ollama + Qwen 2.5 72B)
