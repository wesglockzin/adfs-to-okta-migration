ADFS to Okta SAML Migration — Export-ADFSRelyingPartyTrusts.ps1
================================================================

Pulls one or more ADFS Relying Party Trusts from the local farm, dumps each
into its own folder with a config dump, the SAML signing/encryption certs as
PEM, and Okta-side translation notes for the access control policy. Builds
a master CSV of every selected RPT and a Migration Analysis report at the
top level. Auto-detects DEV / STG / PROD from the local Federation Service
hostname so the same script runs unchanged across environments.

Current version: 6.1


Requirements
------------
- Must run on the ADFS server itself (uses local AD FS PowerShell module).
- Must be launched as Administrator AND from an account that's in the ADFS
  service admin group. Without both, you get:
    ADMIN0120: The client is not authorized to access the endpoint
    net.tcp://localhost:1500/policy.
- PowerShell 5.1+ (Windows Server with Desktop Experience — the picker uses
  WinForms).


Run
---
    # default — only enabled RPTs in the picker
    .\Export-ADFSRelyingPartyTrusts.ps1

    # include disabled RPTs in the picker too
    .\Export-ADFSRelyingPartyTrusts.ps1 -IncludeDisabled


Picker UI (v6.1)
----------------
A WinForms dialog opens showing every RPT (filtered by enabled/disabled
per the param above), sortable by column.

  Filter box       — type to live-narrow by Name (substring, case-insensitive)
  Check All        — checks every CURRENTLY VISIBLE row (respects filter)
  Uncheck All      — unchecks every CURRENTLY VISIBLE row
  Row checkbox     — click to toggle individually
  Column headers   — click to sort
  Status bar       — live count of "N selected — showing visible / total"
  OK               — proceed with checked rows
  Cancel / Esc / X — exit, no folder created

Filtering does not change checked state. Pattern: filter to "westlaw",
Check All, clear filter — only Westlaw rows stay checked.


Output layout
-------------
All output lands under:
    C:\Temp\ADFS_Migration_<ENV>_<YYYYMMDD_HHMMSS>\

  ADFS_Migration_PROD_20260428_132809\
  ├── ADFS_to_Okta_Master_PROD_20260428_132809.csv   ← row per selected RPT
  ├── Migration_Analysis_PROD_20260428_132809.txt    ← summary + review list
  ├── <App Name 1>\
  │   ├── <AppName>_config.txt                       ← human-readable dump
  │   ├── <AppName>_signing.pem                      ← if cert present
  │   ├── <AppName>_encryption.pem                   ← if cert present
  │   ├── <AppName> OKTA IDP.txt                     ← empty placeholder
  │   └── <AppName> OKTA IDP METADATA.xml            ← stub placeholder
  └── <App Name 2>\
      └── ...

Folder names are sanitized (\ / : * ? " < > | replaced with _).
Timestamped output dirs mean re-runs never overwrite earlier exports.


Per-app config file (<AppName>_config.txt)
------------------------------------------
- App Name, SSO URL (first ACS), Entity ID, NameID format
- RequiresReview flag (TRUE if policy can't be auto-mapped to Okta cleanly)
- Cert filenames (or "None")
- Full list of Requestable SSO URLs (every ACS endpoint with its index)
- Attribute Statements with AD-attr → Okta-attr mapping
  (unmapped attrs flagged "[UNMAPPED - verify in Okta]")
- Access Control Policy section: original policy name + permitted/MFA
  groups + Okta translation notes
- Raw IssuanceTransformRules (the unparsed claim rule language)
- ADFS Notes field, Enabled flag


Master CSV (ADFS_to_Okta_Master_<ENV>_<TS>.csv)
------------------------------------------------
One row per selected RPT. Columns:
  Environment, AppName, FolderName, SSO_URL, EntityID, NameIdFormat,
  AuthnRequestsSigned, EndpointCount, AccessControlPolicy, PolicyCategory,
  AssignmentGroups, OktaStrategy, RequiresReview, HasSigningCert,
  HasEncryptionCert, Enabled


Analysis report (Migration_Analysis_<ENV>_<TS>.txt)
----------------------------------------------------
- Total selected RPTs
- Access Control Policy breakdown (count by policy name, descending)
- Okta migration strategy primer per category
- Apps Requiring Manual Review section (flagged + reason)
- Migration recommendations (priority review, group mapping, MFA, certs)
- Full app list grouped by policy


Policy categories the script recognizes
---------------------------------------
  Universal Access + MFA Group         → All users + MFA group ref
  Universal Access + Universal MFA     → All users
  Restricted Access + MFA              → Group-based assignment
  Restricted Access + Network Zone     → Group + zone           (REVIEW)
  Universal Access Only                → All users, no MFA      (REVIEW)
  Custom Policy / Error / No Policy    → Manual review          (REVIEW)


AD attribute → Okta attribute mappings
---------------------------------------
Hardcoded in $attributeMap. Covers the common identity attrs:
mail, givenName, sn, userPrincipalName, samaccountname, displayName, title,
department, telephoneNumber, mobile, company, manager, employeeNumber,
objectSid, objectGUID, middleName, streetAddress, city, state, postalCode,
countryCode, costCenter, division, organization, memberOf.

Unmapped attributes are emitted with "[UNMAPPED - verify in Okta]" so they
show up in the config file for manual review.


Environment detection
---------------------
Detected from (Get-AdfsProperties).HostName — keep this table in sync if
host names change:
    host.example.gov  → DEV
    host.example.gov  → STG
    host.example.gov    → PROD
    anything else      → UNKNOWN  (script still runs; folder labeled UNKNOWN)


Version history
---------------
6.1  2026-04-28  WinForms checkbox picker (filter + Check All / Uncheck All)
6.0  2026-04-28  (transient) Out-GridView picker
5.x  earlier     -IncludeDisabled switch only, processed every RPT
