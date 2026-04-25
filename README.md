> **Reduces manual ADFS-to-Okta migration from hours-per-app to a
> repeatable dry-run workflow with conflict detection, idempotent
> re-runs, and full audit logs.**

# ADFS to Okta Migration

A Flask web tool that automates migrating ADFS Relying Party Trusts to Okta SAML 2.0 applications, using config files produced by an ADFS export script.

---

### About this repo

This is a sanitized snapshot of internal tooling, published via an
automated review-and-publish pipeline. Internal identifiers
(subscription IDs, resource group names, internal hostnames, email
addresses) are deliberately replaced with placeholders like
`your-subscription-id`, `your-acr-name`, and `your-org`. Replace
these with values appropriate to your environment when adapting
the code.

---

## Overview

Migrating a large ADFS deployment to Okta requires moving each Relying Party Trust as an Okta SAML 2.0 application. Doing this by hand through the Okta Admin Console doesn't scale — there are hundreds of apps with different signing certificates, attribute mappings, and ACS endpoints. This tool ingests an ADFS export, produces matching Okta apps via the API, and provides a UI to monitor progress and surface conflicts.

The companion PowerShell export (`Export-ADFSRelyingPartyTrusts_v5.ps1`) runs on the source ADFS farm and produces the JSON config files this tool consumes.

## Features

* **Idempotent operations** — running twice doesn't create duplicates
* **Dry-run support** — preview every API call without making changes
* **Per-action logging** — timestamped entries in `logs/` recording create / skip / error
* **Multi-environment** — DEV, STG, PROD with separate token storage
* **Conflict detection** — flags name collisions, certificate mismatches, attribute mapping issues before pushing to Okta
* **Backup before edit** — `backups/<filename>.bak` written before every file mutation

## Technical Stack

* **Backend:** Python 3, Flask
* **Frontend:** Jinja2 templates + minimal CSS
* **Okta integration:** Direct REST API via `okta_saml_import.py`
* **Token storage:** OS keyring under service `adfs-okta-migration`
* **LLM helper:** `llm_client.py` (optional — assists with attribute mapping suggestions)

## Configuration

Tokens are stored per environment in the OS keyring. Run setup once per machine:

```bash
python setup_tokens.py
```

Stores:

* `OKTA_DEV_API_TOKEN`
* `OKTA_STG_API_TOKEN`
* `OKTA_PROD_API_TOKEN`

Target Okta org URLs are defined in the `OKTA_ADMIN_ENVIRONMENTS` dict in `okta_saml_import.py`.

## Workflow

1. Run `Export-ADFSRelyingPartyTrusts_v5.ps1` on the source ADFS farm
2. Drop the resulting JSON files into the working directory
3. Start the web UI: `python app.py`
4. Review the planned migrations in the dashboard (dry-run by default)
5. Approve and execute against the target environment

## Security Conventions

* **All scripts must be idempotent** — running twice is a no-op for already-migrated apps
* **Never hardcode tokens** — keyring is the source of truth
* **Log every API action** — create, skip, and error all written to a timestamped log file in `logs/`
* **Backup before edit** — every file mutation creates `backups/<filename>.bak` first
