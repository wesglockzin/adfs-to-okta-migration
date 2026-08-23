# ADFS to Okta Migration

## TL;DR

Reads an ADFS Relying Party Trust export and creates matching Okta SAML 2.0 apps. Built to migrate hundreds of RPTs into Okta without one-at-a-time admin-console clicks.

Workflow: export from ADFS via the bundled PowerShell script → ZIP the output → upload here → scan against the target Okta tenant → review what's missing vs already present → bulk import.

## What this tool is — and what it isn't

**It is:**
- An ingest path for ADFS RPT exports (JSON + cert files produced by `Export-ADFSRelyingPartyTrusts.ps1`)
- A pre-import scanner — cross-references each RPT against the target Okta tenant, flags missing apps, already-present apps, and apps that need review before import (parse errors, missing certs, attribute mapping issues)
- A bulk-create surface — picks apps, picks an Auth Policy + IDP Routing Rule, calls Okta's API to create them
- Multi-environment (Okta-DEV / Okta-STG / Okta-PROD)
- Idempotent — re-running against the same export won't duplicate apps

**It isn't:**
- **Not a one-way migration** — doesn't delete or modify the ADFS RPT. The RPT stays in ADFS until separately decommissioned (see Phase 2 of the migration plan).
- **Not the cutover** — this creates apps in Okta; it doesn't redirect authentication. App-side IdP URL changes + ADFS Claims Provider Trust changes are separate workstreams.
- **Not Okta Admin** — that manages apps that already exist in Okta. This creates new ones from ADFS sources.

## Quick start — 30 seconds

1. **Step 1 (one time):** Click "Download Export-ADFSRelyingPartyTrusts.ps1" in the empty state, run it on the source ADFS server. Produces a folder of JSON config files + cert files.
2. **Step 2:** ZIP the output folder. Upload via "Upload ZIP…".
3. **Step 3:** Pick target env (DEV / STG / PROD). Click Scan.
4. **Step 4:** Review the table — apps in green are already in Okta, red are missing-and-importable, yellow are review-flagged.
5. **Step 5:** Select apps to import (or use the "Select all missing" checkbox). Pick an Auth Policy + IDP Routing Rule from the dropdowns. Click Import Selected.

## How to use it

### The scan table

| Column | What it shows |
|---|---|
| **App Name** | RPT display name from the ADFS export |
| **ACS Endpoints** | How many ACS URLs the RPT defines (most apps have 1; multi-tenant apps have several) |
| **Enc Cert** | Whether the RPT brought a SAML encryption certificate |
| **Sign Cert** | Whether the RPT brought a SAML signing certificate |
| **Group Assignment** | The Okta group(s) the imported app will be assigned to |
| **Review Flag** | Apps that need manual review before import (parse errors, ambiguous attribute mappings, etc.) |
| **In Okta** | Whether an app with this entity ID already exists in the target tenant |
| **Auth Policy** | The Okta sign-on policy this app will use (populated from the dropdown above) |
| **Routing Rule** | The Okta IdP Discovery routing rule this app will be added to |
| **Status** | Per-row import outcome after running Import Selected |

### Filtering

- **All / Missing / In Okta / Review Flag / Enc Cert** filter pills narrow the visible rows
- Use **Missing** to scope down to "what's left to import"
- Use **Review Flag** to triage anything the scanner flagged as ambiguous before bulk-importing

### Auth Policy + IDP Routing Rule

These two dropdowns are populated live from the target Okta tenant. Picking them BEFORE clicking Import Selected assigns every imported app the chosen policy and routing rule in the same API call — no follow-up sweep needed.

### Import History

Top-right "Import History ↗" link opens a per-action audit log: every create / skip / error from past import runs, with timestamps and operator identity.

### Update existing (policy & groups)

Check this box if you want the import to apply the chosen Auth Policy + IDP Routing Rule + group assignment to apps that ALREADY exist in Okta (otherwise the importer skips them as "already present").

## Common gotchas

- **Parse errors** → the RPT export file is malformed or corrupt. Re-export from ADFS, check for partial writes.
- **Missing signing cert** → SAML 2.0 requires a signing cert. Re-run the export and ensure the source RPT actually has one configured.
- **In Okta but ACS count mismatch** → the app exists in Okta but the ACS URLs differ between ADFS and Okta. Manual reconciliation required — don't bulk-import.
- **Auth Policy / Routing Rule dropdown empty** → token lacks the right Okta scopes, or the target tenant has no policies/rules created. Check the env's keyring token + the Okta admin console.
