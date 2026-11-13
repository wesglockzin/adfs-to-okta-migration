> **Export the Relying Party Trusts from an ADFS farm, upload the bundle,
> scan it against the target Okta org, and create the matching SAML 2.0
> apps through the API — with a log of every run. Built to move hundreds of
> apps without hand-typing a single one in the Admin Console.**

# ADFS to Okta Migration

![ADFS to Okta Migration — scan results](screenshots/migration-tool.png)

---

### About this repo

Source for an internal migration tool, published for community reference.
The tool runs in private infrastructure; screenshots use synthetic app names.
Internal hostnames, tenant and resource names are replaced with placeholders
(`host.example.gov`, `your-resource-group`). The code is the code that runs;
the configuration values are not.

---

## The workflow

1. **Export** — run `scripts/Export-ADFSRelyingPartyTrusts.ps1` (v6.1, a
   WinForms picker with filter and Check All) on the ADFS farm. For each
   selected trust it writes a folder containing `<app>_config.txt` (identifier,
   ACS endpoints, NameID format, claim-rule-derived attribute lines, assignment
   hints) and the trust's signing certificate as PEM. Zip the output.
2. **Upload** — `POST /api/upload` takes the ZIP, extracts it into a per-upload
   working directory and returns a session id.
3. **Scan** — `GET /api/scan` reads every `_config.txt`, pulls the app list
   from the chosen Okta org and reports, per app: already in Okta or not,
   ACS-endpoint count, and anything that needs a human look before import.
4. **Import** — `POST /api/import` creates the missing apps as Okta SAML 2.0
   integrations (ACS URLs, audience, NameID, attribute statements,
   encryption-certificate upload, group/Everyone assignment) and records the
   result. The ADFS *signing* cert is skipped by default — Okta issues its own
   signing certificate for the new app.
5. **Operate** — `/api/toggle-status` activates / deactivates an app;
   `/api/policies` and `/api/routing-rules` list what the org has; `/logs`
   shows past runs from Log Analytics.

The same import logic is available as a CLI —
`python okta_saml_import.py --env dev --input-dir <export> [--app NAME]
[--dry-run] [--skip-certs] [--max-acs N] [--debug]` — and **`--dry-run` is
CLI-only**: the web UI imports when you click Import.

## Optional: AI scan analysis

`/api/analyze-scan` sends the scan summary to the LLM server named by
`LLM_BASE_URL` (`llm_client.py`, see
[identity-llm-client](https://github.com/wesglockzin/identity-llm-client))
and renders its observations in the AI panel. The button renders whenever the
client module imports; it fails at request time if the LLM settings are
missing or the server is down.

## Project layout

| File | Role |
|---|---|
| `settings.py` | Startup auth-mode check and redirect validation |
| `app.py` | Flask app — Okta OIDC gate, upload / scan / import / status APIs, Log Analytics run log |
| `okta_saml_import.py` | Parser for the export format + Okta REST client + CLI |
| `scripts/Export-ADFSRelyingPartyTrusts.ps1` | The export script (runs on ADFS) |
| `backfill-logs.py` | One-shot: push historical run logs into Log Analytics |
| `setup_tokens.py` | Store per-environment Okta API tokens in the OS keyring |
| `llm_client.py` | OpenAI-compatible LLM client for the AI panel (configured by environment variables) |
| `templates/` | `index.html`, `logs.html` |
| `Dockerfile`, `setup-azure.sh` | Container image and one-time Azure Container Apps setup |

## Configuration

**Okta API tokens** — one per environment, stored in the OS keyring by
`python setup_tokens.py` (`OKTA_DEV_API_TOKEN`, `OKTA_STG_API_TOKEN`,
`OKTA_PROD_API_TOKEN`); in Azure Container Apps the same names are secrets
injected as environment variables. Org URLs live in the
`OKTA_ADMIN_ENVIRONMENTS` dict in `okta_saml_import.py`.

**Sign-in gate** — `AUTH_MODE` (`oidc` by default, or `none`),
`OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `APP_BASE_URL`,
`FLASK_SECRET_KEY`. Okta OIDC, authorization code + PKCE; access is decided
by assignment on the Okta app. **The app refuses to start** unless all of the
`OIDC_*` settings and `FLASK_SECRET_KEY` are set, or `AUTH_MODE=none` is set
explicitly (no sign-in; local use only).

**Listening address** — `PORT` (default 5001) and `HOST` (default
`127.0.0.1`; the container image sets `0.0.0.0` and `PORT=8080`).

**Run log** — `LA_WORKSPACE_ID` / `LA_WORKSPACE_KEY` (write) and a managed
identity with Log Analytics Reader (read) for `/logs`. `LA_TABLE_NAME`
(default `ADFSImportRuns`), `LA_RESOURCE_ID` for queries.

**AI panel (optional, no defaults)** — `LLM_BASE_URL` (OpenAI-compatible
server), `LLM_MODEL_REASON`, `LLM_MODEL_FAST`, `LLM_MODEL_EMBED`. A missing
one fails the request with the setting's name.

Every setting is listed in `.env.example`.

## Running it

Type: web service with a command-line importer.

```bash
pip install -e .
adfs-to-okta-setup-tokens       # once per machine (optional keyring)
python app.py                   # http://localhost:5001 (set AUTH_MODE=none locally)
adfs-to-okta --env dev --input-dir <export> --dry-run   # CLI importer
```

Tests: `pip install -e ".[dev]" && pytest`.

The container runs gunicorn with one worker and 8 threads, because upload
sessions live in process memory. `setup-azure.sh` creates the Azure Container
App once.

## Known limitations

Real, known, in the order I intend to fix them.

- **Upload sessions are in-process memory.** The container therefore runs one
  gunicorn worker; do not scale to more workers or replicas until uploads are
  resolved from shared storage.
- **Okta org URLs are a fixed dev/stg/prod table** in `okta_saml_import.py`
  (placeholders in this snapshot); they are not yet environment settings.
- **Lockfile, formatter run and CI workflow are not yet in place.**
- **Apps whose ADFS assignment can't be parsed default to Everyone** on
  import (Custom Policy trusts, lookup errors). The scan flags them for
  review; the import does not yet refuse them.
- **`run_id` is interpolated into the Log Analytics query** without
  validation; it should be checked as 32-hex before use.
- **Duplicate-label lookup is a prefix search** (`?q=`, 10 results), so an
  org with many similar labels can miss an exact match and create a duplicate.
- The AI panel's HTML is built with `innerHTML`; app names from the export
  should be escaped.
- Tests cover the config parser, settings checks, the auth gate, redirect
  validation and Okta/LLM client error paths; the import and scan routes are
  not yet covered.

## Version

`APP_VERSION` in `app.py` is authoritative (currently 2.0.x); the export
script carries its own version in its header.

## License

MIT — see [LICENSE](LICENSE).

## Author

Wes Glockzin
