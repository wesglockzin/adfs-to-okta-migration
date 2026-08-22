# ADFS to Okta SAML Migration - Multi-Environment Folder Structure Generator
# Version: 6.1  (2026-04-28 — WinForms checkbox picker with filter + Check All)
# Creates individual folders with config files and PEM certificates
# Automatically detects ADFS environment from Federation Service Name
# Includes SAML endpoints and Access Control Policies with intelligent Okta translation
# Generates migration analysis report
# Timestamps output folders to prevent overwrites

param(
    [switch]$IncludeDisabled
)

# Detect ADFS environment from Federation Service Name
$adfsFederationServiceName = (Get-AdfsProperties).HostName.ToLower()

$envSuffix = switch ($adfsFederationServiceName) {
    "host.example.gov" { "DEV" }
    "host.example.gov" { "STG" }
    "host.example.gov"   { "PROD" }
    default             { "UNKNOWN" }
}

# Add timestamp to output folder
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$rootPath     = "C:\Temp\ADFS_Migration_$($envSuffix)_$timestamp"
$csvPath      = "$rootPath\ADFS_to_Okta_Master_$($envSuffix)_$timestamp.csv"
$analysisPath = "$rootPath\Migration_Analysis_$($envSuffix)_$timestamp.txt"

Write-Host "=========================================="
Write-Host "Script Version: 6.1"
Write-Host "Detected ADFS Environment: $envSuffix"
Write-Host "ADFS Federation Service: $adfsFederationServiceName"
Write-Host "Timestamp: $timestamp"
Write-Host "Output Path: $rootPath"
Write-Host "=========================================="

# AD Attribute to Okta Attribute Mapping
$attributeMap = @{
    'mail'              = 'email -> user.email'
    'givenName'         = 'firstname -> user.firstName'
    'sn'                = 'lastname -> user.lastName'
    'userPrincipalName' = 'upn -> user.login'
    'samaccountname'    = 'samaccountname -> user.samaccountname'
    'displayName'       = 'displayName -> user.displayName'
    'title'             = 'title -> user.title'
    'department'        = 'department -> user.department'
    'telephoneNumber'   = 'primaryPhone -> user.primaryPhone'
    'mobile'            = 'mobilePhone -> user.mobilePhone'
    'company'           = 'company -> user.company'
    'manager'           = 'manager -> user.manager'
    'employeeNumber'    = 'employeeNumber -> user.employeeNumber'
    'objectSid'         = 'objectSid -> user.objectSid'
    'objectGUID'        = 'externalId -> user.externalId'
    'middleName'        = 'middleName -> user.middleName'
    'streetAddress'     = 'streetAddress -> user.streetAddress'
    'city'              = 'city -> user.city'
    'state'             = 'state -> user.state'
    'postalCode'        = 'zipCode -> user.zipCode'
    'countryCode'       = 'countryCode -> user.countryCode'
    'costCenter'        = 'costCenter -> user.costCenter'
    'division'          = 'division -> user.division'
    'organization'      = 'organization -> user.organization'
    'memberOf'          = 'memberOf -> user.memberOf'
}

$results = @()
$policyStats = @{}

# ============================================================
# RPT Picker - WinForms checkbox dialog with filter + Check All
# ============================================================
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$allRpts = Get-AdfsRelyingPartyTrust |
    Where-Object { $IncludeDisabled -or $_.Enabled } |
    Sort-Object Name

if (-not $allRpts) {
    Write-Host "`nNo RPTs found." -ForegroundColor Yellow
    return
}

# Backing DataTable for live filtering via DataView.RowFilter
$dt = New-Object System.Data.DataTable
[void]$dt.Columns.Add("Selected",   [bool])
[void]$dt.Columns.Add("Name",       [string])
[void]$dt.Columns.Add("Enabled",    [bool])
[void]$dt.Columns.Add("Identifier", [string])
[void]$dt.Columns.Add("__index",    [int])

for ($i = 0; $i -lt $allRpts.Count; $i++) {
    $row = $dt.NewRow()
    $row["Selected"]   = $false
    $row["Name"]       = $allRpts[$i].Name
    $row["Enabled"]    = $allRpts[$i].Enabled
    $row["Identifier"] = $allRpts[$i].Identifier[0]
    $row["__index"]    = $i
    [void]$dt.Rows.Add($row)
}
$dv = $dt.DefaultView

$form = New-Object System.Windows.Forms.Form
$form.Text          = "Select RPTs to export - $($allRpts.Count) available"
$form.Size          = New-Object System.Drawing.Size(720, 620)
$form.MinimumSize   = New-Object System.Drawing.Size(500, 400)
$form.StartPosition = 'CenterScreen'

$lblFilter = New-Object System.Windows.Forms.Label
$lblFilter.Text     = "Filter:"
$lblFilter.Location = New-Object System.Drawing.Point(10, 13)
$lblFilter.Size     = New-Object System.Drawing.Size(45, 20)
$form.Controls.Add($lblFilter)

$txtFilter = New-Object System.Windows.Forms.TextBox
$txtFilter.Location = New-Object System.Drawing.Point(55, 10)
$txtFilter.Size     = New-Object System.Drawing.Size(360, 25)
$txtFilter.Anchor   = 'Top, Left, Right'
$form.Controls.Add($txtFilter)

$btnCheckAll = New-Object System.Windows.Forms.Button
$btnCheckAll.Text     = "Check All (visible)"
$btnCheckAll.Location = New-Object System.Drawing.Point(425, 9)
$btnCheckAll.Size     = New-Object System.Drawing.Size(130, 27)
$btnCheckAll.Anchor   = 'Top, Right'
$form.Controls.Add($btnCheckAll)

$btnUncheckAll = New-Object System.Windows.Forms.Button
$btnUncheckAll.Text     = "Uncheck All (visible)"
$btnUncheckAll.Location = New-Object System.Drawing.Point(560, 9)
$btnUncheckAll.Size     = New-Object System.Drawing.Size(140, 27)
$btnUncheckAll.Anchor   = 'Top, Right'
$form.Controls.Add($btnUncheckAll)

$grid = New-Object System.Windows.Forms.DataGridView
$grid.Location              = New-Object System.Drawing.Point(10, 45)
$grid.Size                  = New-Object System.Drawing.Size(685, 480)
$grid.Anchor                = 'Top, Bottom, Left, Right'
$grid.AllowUserToAddRows    = $false
$grid.AllowUserToDeleteRows = $false
$grid.RowHeadersVisible     = $false
$grid.AutoGenerateColumns   = $false
$grid.SelectionMode         = 'FullRowSelect'
$grid.MultiSelect           = $true
$grid.EditMode              = 'EditOnEnter'

$col1 = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
$col1.HeaderText       = ""
$col1.Width            = 30
$col1.DataPropertyName = "Selected"
[void]$grid.Columns.Add($col1)

$col2 = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$col2.HeaderText       = "Name"
$col2.Width            = 380
$col2.DataPropertyName = "Name"
$col2.ReadOnly         = $true
[void]$grid.Columns.Add($col2)

$col3 = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
$col3.HeaderText       = "Enabled"
$col3.Width            = 65
$col3.DataPropertyName = "Enabled"
$col3.ReadOnly         = $true
[void]$grid.Columns.Add($col3)

$col4 = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$col4.HeaderText       = "Identifier"
$col4.Width            = 200
$col4.DataPropertyName = "Identifier"
$col4.ReadOnly         = $true
[void]$grid.Columns.Add($col4)

$grid.DataSource = $dv
$form.Controls.Add($grid)

$btnOK = New-Object System.Windows.Forms.Button
$btnOK.Text          = "OK"
$btnOK.Location      = New-Object System.Drawing.Point(515, 535)
$btnOK.Size          = New-Object System.Drawing.Size(85, 30)
$btnOK.Anchor        = 'Bottom, Right'
$btnOK.DialogResult  = 'OK'
$form.Controls.Add($btnOK)
$form.AcceptButton   = $btnOK

$btnCancel = New-Object System.Windows.Forms.Button
$btnCancel.Text          = "Cancel"
$btnCancel.Location      = New-Object System.Drawing.Point(610, 535)
$btnCancel.Size          = New-Object System.Drawing.Size(85, 30)
$btnCancel.Anchor        = 'Bottom, Right'
$btnCancel.DialogResult  = 'Cancel'
$form.Controls.Add($btnCancel)
$form.CancelButton       = $btnCancel

$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Location = New-Object System.Drawing.Point(10, 540)
$lblStatus.Size     = New-Object System.Drawing.Size(500, 20)
$lblStatus.Anchor   = 'Bottom, Left'
$lblStatus.Text     = "0 selected"
$form.Controls.Add($lblStatus)

$updateStatus = {
    $count   = @($dt.Rows | Where-Object { $_.Selected -eq $true }).Count
    $visible = $dv.Count
    $lblStatus.Text = "$count selected  -  showing $visible / $($dt.Rows.Count)"
}.GetNewClosure()

$txtFilter.Add_TextChanged({
    [void]$grid.EndEdit()
    $q = $txtFilter.Text -replace "'", "''"
    if ([string]::IsNullOrWhiteSpace($q)) {
        $dv.RowFilter = ""
    } else {
        $dv.RowFilter = "Name LIKE '%$q%'"
    }
    & $updateStatus
}.GetNewClosure())

$btnCheckAll.Add_Click({
    [void]$grid.EndEdit()
    foreach ($r in $dv) { $r["Selected"] = $true }
    & $updateStatus
}.GetNewClosure())

$btnUncheckAll.Add_Click({
    [void]$grid.EndEdit()
    foreach ($r in $dv) { $r["Selected"] = $false }
    & $updateStatus
}.GetNewClosure())

# Commit checkbox edits immediately on click rather than waiting for row-leave
$grid.Add_CurrentCellDirtyStateChanged({
    if ($grid.IsCurrentCellDirty) { $grid.CommitEdit('Commit') }
})
$grid.Add_CellValueChanged({ & $updateStatus }.GetNewClosure())

& $updateStatus
$result = $form.ShowDialog()

if ($result -ne [System.Windows.Forms.DialogResult]::OK) {
    Write-Host "`nNo selection - exiting." -ForegroundColor Yellow
    return
}

$rpTrusts = @()
foreach ($row in $dt.Rows) {
    if ($row["Selected"] -eq $true) {
        $rpTrusts += $allRpts[$row["__index"]]
    }
}

if (-not $rpTrusts) {
    Write-Host "`nNothing checked - exiting." -ForegroundColor Yellow
    return
}

# Create root directory only after selection (no empty folder if user cancels)
if (!(Test-Path $rootPath)) {
    New-Item -Path $rootPath -ItemType Directory | Out-Null
}

Write-Host "`nProcessing $($rpTrusts.Count) Relying Party Trust(s)...`n"

foreach ($rp in $rpTrusts) {

    # Sanitize folder name (remove invalid characters)
    $folderName = $rp.Name -replace '[\\/:*?"<>|]', '_'
    $appFolderPath = Join-Path $rootPath $folderName

    # Create app folder
    New-Item -Path $appFolderPath -ItemType Directory -Force | Out-Null

    # Create placeholder Okta IDP file per app
    $oktaIdpFileName = "$folderName OKTA IDP.txt"
    $oktaIdpFilePath = Join-Path $appFolderPath $oktaIdpFileName
    New-Item -Path $oktaIdpFilePath -ItemType File -Force | Out-Null

    # Create placeholder Okta IDP metadata file per app
    $oktaIdpMetadataFileName = "$folderName OKTA IDP METADATA.xml"
    $oktaIdpMetadataFilePath = Join-Path $appFolderPath $oktaIdpMetadataFileName
    $oktaIdpMetadataContent = '<?xml version="1.0" encoding="UTF-8"?>`n<Metadata>PLACEHOLDER</Metadata>'
    $oktaIdpMetadataContent | Out-File -FilePath $oktaIdpMetadataFilePath -Encoding ASCII

    # Parse NameID format - extract just the final value
    $nameIdFormat = "unspecified"
    if ($rp.IssuanceTransformRules -match 'claimproperties/format"\]\s*=\s*"[^"]*:([^"]+)"') {
        $nameIdFormat = $matches[1]
    } elseif ($rp.IssuanceTransformRules -match 'nameidentifier.*emailAddress') {
        $nameIdFormat = "emailAddress"
    } elseif ($rp.IssuanceTransformRules -match 'nameid-format:([A-Za-z0-9._-]+)') {
        $nameIdFormat = $matches[1]
    }

    # Parse attribute statements with Okta mapping
    $attributeStatements = @()
    $typeMatches  = [regex]::Matches($rp.IssuanceTransformRules, 'types\s*=\s*\(([^)]+)\)')
    $queryMatches = [regex]::Matches($rp.IssuanceTransformRules, 'query\s*=\s*"([^"]+)"')

    for ($i = 0; $i -lt $typeMatches.Count; $i++) {
        if ($i -lt $queryMatches.Count) {
            $claimTypes = $typeMatches[$i].Groups[1].Value -replace '"', '' -split ',\s*'
            $queryParts = $queryMatches[$i].Groups[1].Value -split ';'
            if ($queryParts.Count -ge 2) {
                $adAttributes = $queryParts[1] -split ',\s*'
                for ($j = 0; $j -lt [Math]::Min($claimTypes.Count, $adAttributes.Count); $j++) {
                    $adAttr = $adAttributes[$j].Trim()
                    if ($attributeMap.ContainsKey($adAttr)) {
                        $attributeStatements += "  $($attributeMap[$adAttr])"
                    } else {
                        $attributeStatements += "  $adAttr -> [UNMAPPED - verify in Okta]"
                    }
                }
            }
        }
    }

    # Extract Access Control Policy information
    $accessPolicySection = ""
    $accessPolicyName = ""
    $mfaGroups = @()
    $permittedGroups = @()
    $policyCategory = ""
    $oktaStrategy = ""
    $requiresReview = $false

    if ($rp.AccessControlPolicyName) {
        $accessPolicyName = $rp.AccessControlPolicyName

        if (!$policyStats.ContainsKey($accessPolicyName)) {
            $policyStats[$accessPolicyName] = @{ Count = 0; Apps = @() }
        }
        $policyStats[$accessPolicyName].Count++
        $policyStats[$accessPolicyName].Apps += $rp.Name

        try {
            $policy = Get-AdfsAccessControlPolicy -Name $rp.AccessControlPolicyName

            if ($rp.AccessControlPolicyParameters) {
                foreach ($key in $rp.AccessControlPolicyParameters.Keys) {
                    if ($key -like "GroupParameter*") {
                        $groupValue = $rp.AccessControlPolicyParameters[$key]
                        if ($policy.Name -match "require MFA" -and $policy.Name -match "for specific group") {
                            $mfaGroups += $groupValue
                        } else {
                            $permittedGroups += $groupValue
                        }
                    }
                }
            }

            switch -Regex ($policy.Name) {
                "Permit everyone and require MFA for specific group" {
                    $policyCategory = "Universal Access + MFA Group"
                    $oktaStrategy   = "All users + MFA group reference"
                }
                "Permit everyone and require MFA$" {
                    $policyCategory = "Universal Access + Universal MFA"
                    $oktaStrategy   = "All users"
                }
                "Permit.*from specific group and require MFA" {
                    $policyCategory = "Restricted Access + MFA"
                    $oktaStrategy   = "Group-based assignment"
                }
                "Permit.*and require Intranet" {
                    $policyCategory = "Restricted Access + Network Zone"
                    $oktaStrategy   = "Group + Network zone"
                    $requiresReview = $true
                }
                "Permit everyone$" {
                    $policyCategory = "Universal Access Only"
                    $oktaStrategy   = "All users"
                    $requiresReview = $true
                }
                default {
                    $policyCategory = "Custom Policy"
                    $oktaStrategy   = "Manual review required"
                    $requiresReview = $true
                }
            }

            $accessPolicySection = "`nAccess Control Policy: $($policy.Name)"

            if ($permittedGroups.Count -gt 0) {
                $accessPolicySection += "`nPermitted Group(s):"
                foreach ($group in $permittedGroups) {
                    $accessPolicySection += "`n  - $group"
                }
            }

            if ($mfaGroups.Count -gt 0) {
                $accessPolicySection += "`nMFA Required For Group(s):"
                foreach ($group in $mfaGroups) {
                    $accessPolicySection += "`n  - $group"
                }
            }

            $accessPolicySection += "`n`nOkta Translation Notes:"

            switch ($policyCategory) {
                "Universal Access + MFA Group" {
                    $accessPolicySection += "`n- Create assignment rule for all users"
                    $accessPolicySection += "`n- org-wide MFA policy applies to all users by default"
                    foreach ($group in $mfaGroups) {
                        $oktaGroupName = $group -replace '^[^\\]+\\', ''
                        $accessPolicySection += "`n- MFA group documented for reference: `"$oktaGroupName`""
                        $accessPolicySection += "`n  (Retained for potential policy exceptions or modifications)"
                    }
                }
                "Universal Access + Universal MFA" {
                    $accessPolicySection += "`n- Create assignment rule for all users"
                    $accessPolicySection += "`n- org-wide MFA policy applies (redundant with ADFS policy)"
                }
                "Restricted Access + MFA" {
                    foreach ($group in $permittedGroups) {
                        $oktaGroupName = $group -replace '^[^\\]+\\', ''
                        $accessPolicySection += "`n- Create assignment rule for group: `"$oktaGroupName`""
                    }
                    $accessPolicySection += "`n- org-wide MFA policy applies"
                }
                "Restricted Access + Network Zone" {
                    foreach ($group in $permittedGroups) {
                        $oktaGroupName = $group -replace '^[^\\]+\\', ''
                        $accessPolicySection += "`n- Create assignment rule for group: `"$oktaGroupName`""
                    }
                    $accessPolicySection += "`n- Configure network zone restriction (Intranet/On-Network)"
                    $accessPolicySection += "`n- org-wide MFA policy applies"
                }
                "Universal Access Only" {
                    $accessPolicySection += "`n- Create assignment rule for all users"
                    $accessPolicySection += "`n- WARNING: No MFA enforcement in ADFS - verify if org-wide Okta MFA should apply"
                }
                default {
                    $accessPolicySection += "`n- MANUAL REVIEW REQUIRED: Custom or complex policy"
                    $accessPolicySection += "`n- Analyze ADFS policy details before configuring Okta"
                }
            }

        } catch {
            $accessPolicySection = "`nAccess Control Policy: $($rp.AccessControlPolicyName)"
            $accessPolicySection += "`n[Error retrieving policy details: $($_.Exception.Message)]"
            $policyCategory = "Error"
            $oktaStrategy   = "Review required"
            $requiresReview = $true
        }
    } else {
        $accessPolicySection = "`nAccess Control Policy: None configured"
        $accessPolicySection += "`n`nOkta Translation Notes:"
        $accessPolicySection += "`n- Create assignment rule for all users"
        $accessPolicySection += "`n- WARNING: No access control policy in ADFS - verify requirements"

        $policyCategory = "No Policy"
        $oktaStrategy   = "Review required"
        $requiresReview = $true

        if (!$policyStats.ContainsKey("No Policy Assigned")) {
            $policyStats["No Policy Assigned"] = @{ Count = 0; Apps = @() }
        }
        $policyStats["No Policy Assigned"].Count++
        $policyStats["No Policy Assigned"].Apps += $rp.Name
    }

    # Extract all SAML endpoints (Requestable SSO URLs)
    $acsEndpoints = $rp.SamlEndpoints | Where-Object {$_.Protocol -eq "SAMLAssertionConsumer"} | Sort-Object Index
    $endpointsList = @()
    foreach ($endpoint in $acsEndpoints) {
        $endpointsList += "  [$($endpoint.Index)] $($endpoint.Location)"
    }

    $ssoUrl = if ($acsEndpoints.Count -gt 0) { $acsEndpoints[0].Location } else { "" }

    # Handle certificates with RPT-named files
    $signingCertFile = ""
    $encryptionCertFile = ""

    $authnRequestsSigned = $false
    if ($rp.RequestSigningCertificate -and $rp.RequestSigningCertificate.Count -gt 0) {
        $authnRequestsSigned = $true
    }
    $authnRequestsSignedText = if ($authnRequestsSigned) { "TRUE" } else { "FALSE" }

    if ($rp.RequestSigningCertificate) {
        $signingCertFile = "$($folderName)_signing.pem"
        $signingPemPath  = Join-Path $appFolderPath $signingCertFile
        $signingCertBase64 = [Convert]::ToBase64String($rp.RequestSigningCertificate[0].RawData)

        $pemContent  = "-----BEGIN CERTIFICATE-----`n"
        $pemContent += ($signingCertBase64 -replace '(.{64})', "`$1`n")
        $pemContent += "`n-----END CERTIFICATE-----"
        $pemContent | Out-File -FilePath $signingPemPath -Encoding ASCII
    }

    if ($rp.EncryptionCertificate) {
        $encryptionCertFile = "$($folderName)_encryption.pem"
        $encryptionPemPath  = Join-Path $appFolderPath $encryptionCertFile
        $encryptionCertBase64 = [Convert]::ToBase64String($rp.EncryptionCertificate.RawData)

        $pemContent  = "-----BEGIN CERTIFICATE-----`n"
        $pemContent += ($encryptionCertBase64 -replace '(.{64})', "`$1`n")
        $pemContent += "`n-----END CERTIFICATE-----"
        $pemContent | Out-File -FilePath $encryptionPemPath -Encoding ASCII
    }

    $configContent = @"
App Name: $($rp.Name)
SSO URL: $ssoUrl
Entity ID: $($rp.Identifier[0])
Name ID Format: $nameIdFormat
RequiresReview: $(if ($requiresReview) { "TRUE" } else { "FALSE" })

Signing Certificate: $(if ($signingCertFile) { $signingCertFile } else { "None" })
Encryption Certificate: $(if ($encryptionCertFile) { $encryptionCertFile } else { "None" })

Requestable SSO URLs ($($acsEndpoints.Count) total):
$($endpointsList -join "`n")

Attribute Statements:
$($attributeStatements -join "`n")
$accessPolicySection

Raw Issuance Transform Rules:
$($rp.IssuanceTransformRules)

Notes: $($rp.Notes)
Enabled: $($rp.Enabled)
"@

    $configFileName = "$($folderName)_config.txt"
    $configPath     = Join-Path $appFolderPath $configFileName
    $configContent | Out-File -FilePath $configPath -Encoding UTF8

    $allGroups = ($permittedGroups + $mfaGroups) -join "; "

    $results += [PSCustomObject]@{
        Environment         = $envSuffix
        AppName             = $rp.Name
        FolderName          = $folderName
        SSO_URL             = $ssoUrl
        EntityID            = $rp.Identifier[0]
        NameIdFormat        = $nameIdFormat
        AuthnRequestsSigned = $authnRequestsSignedText
        EndpointCount       = $acsEndpoints.Count
        AccessControlPolicy = $accessPolicyName
        PolicyCategory      = $policyCategory
        AssignmentGroups    = $allGroups
        OktaStrategy        = $oktaStrategy
        RequiresReview      = $requiresReview
        HasSigningCert      = ($signingCertFile -ne "")
        HasEncryptionCert   = ($encryptionCertFile -ne "")
        Enabled             = $rp.Enabled
    }

    Write-Host "  [OK] $($rp.Name) [$($acsEndpoints.Count) endpoints] - $policyCategory"
}

# Export master CSV
$results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

# Generate Migration Analysis Report
$analysisContent = @"
========================================
ADFS to Okta SAML Migration Analysis
========================================

Script Version: 6.1
Environment: $envSuffix
ADFS Federation Service: $adfsFederationServiceName
Extraction Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Selected Relying Party Trusts: $($rpTrusts.Count)

========================================
ACCESS CONTROL POLICY BREAKDOWN
========================================

"@

$sortedPolicies = $policyStats.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending

$policyNumber = 1
foreach ($policy in $sortedPolicies) {
    $analysisContent += "`n$policyNumber. ""$($policy.Key)"" - $($policy.Value.Count) apps`n"
    $policyNumber++
}

$analysisContent += @"

========================================
OKTA MIGRATION STRATEGIES
========================================

Universal Access + MFA Group:
- Most common pattern in environment
- Assign all users to app in Okta
- Document MFA groups for future reference
- org-wide MFA policy handles enforcement

Universal Access + Universal MFA:
- Simple migration path
- Assign all users to app in Okta
- org-wide MFA policy redundant with ADFS

Restricted Access + MFA:
- Group-based assignment required
- Map ADFS groups to Okta groups
- org-wide MFA policy applies

Restricted Access + Network Zone:
- Group-based assignment required
- Configure Okta network zones for Intranet restriction
- May require additional testing/validation

No Policy / Custom Policy:
- Requires manual review before migration
- Verify intended access control and MFA requirements

========================================
APPS REQUIRING MANUAL REVIEW
========================================

"@

$reviewApps = $results | Where-Object { $_.RequiresReview -eq $true }
$analysisContent += "Total apps flagged for review: $($reviewApps.Count)`n`n"

foreach ($app in $reviewApps) {
    $analysisContent += "- $($app.AppName)`n"
    $analysisContent += "  Policy: $($app.AccessControlPolicy)`n"
    $analysisContent += "  Category: $($app.PolicyCategory)`n"
    $analysisContent += "  Reason: $(if ($app.PolicyCategory -match 'Network Zone') { 'Network restriction requires Okta zone configuration' } elseif ($app.PolicyCategory -eq 'No Policy') { 'No access control policy defined' } elseif ($app.PolicyCategory -eq 'Universal Access Only') { 'No MFA enforcement in ADFS' } else { 'Custom or complex policy requires analysis' })`n`n"
}

$analysisContent += @"

========================================
MIGRATION RECOMMENDATIONS
========================================

1. PRIORITY REVIEW:
   - Review all $($reviewApps.Count) apps flagged for manual review
   - Validate network zone requirements for Intranet-only apps
   - Confirm MFA enforcement strategy matches the organization security policy

2. GROUP MAPPING:
   - Create Okta groups corresponding to ADFS assignment groups
   - Document group membership requirements
   - Test group-based assignment in DEV/STG before PROD

3. MFA CONFIGURATION:
   - Verify org-wide Okta MFA policy is configured
   - Document any app-specific MFA exceptions
   - Test MFA enforcement across all policy types

4. CERTIFICATE MANAGEMENT:
   - $($results | Where-Object { $_.HasSigningCert } | Measure-Object | Select-Object -ExpandProperty Count) apps have signing certificates
   - $($results | Where-Object { $_.HasEncryptionCert } | Measure-Object | Select-Object -ExpandProperty Count) apps have encryption certificates
   - Upload certificates during Okta SAML app creation

5. TESTING PLAN:
   - Test each policy category in DEV environment
   - Validate SSO, MFA, and group assignment
   - Verify all requestable SSO URLs work correctly

========================================
POLICY DETAILS BY APP COUNT
========================================

"@

foreach ($policy in $sortedPolicies) {
    $analysisContent += "`n""$($policy.Key)"" ($($policy.Value.Count) apps):`n"
    $analysisContent += "----------------------------------------`n"
    foreach ($appName in ($policy.Value.Apps | Sort-Object)) {
        $analysisContent += "  - $appName`n"
    }
}

$analysisContent += @"

========================================
END OF ANALYSIS
========================================
"@

$analysisContent | Out-File -FilePath $analysisPath -Encoding UTF8

Write-Host "`n=========================================="
Write-Host "[OK] Created $($results.Count) folders in $rootPath"
Write-Host "[OK] Master CSV exported to $csvPath"
Write-Host "[OK] Migration analysis exported to $analysisPath"
Write-Host "[OK] Apps requiring review: $($reviewApps.Count)"
Write-Host "=========================================="
