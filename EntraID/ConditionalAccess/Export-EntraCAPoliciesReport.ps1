<#
.SYNOPSIS
    Export Conditional Access (CA) policies from Microsoft Entra ID (Azure AD) to a structured CSV file.
.DESCRIPTION
    This script uses Microsoft Graph (beta) to extract Conditional Access policy configurations into a timestamped CSV report
    for audit, compliance, and operational insight.
    Key Features:
      • Filters: Active, Disabled, Report-Only, recently created or modified
      • Output: CSV file with 30+ core CA policy attributes
      • Column handling: Optional exclusion of empty columns
      • Authentication: Supports interactive and certificate-based Graph auth
      • Progress: Includes progress bar with per-policy feedback (safe for divide-by-zero cases)
      • Performance: Caches display names and uses optimized object creation
      • Reliability: Verifies module presence and avoids redundant imports
      • Hygiene: Disconnects from Graph after execution and suppresses disconnect output
      • Verbose Mode: Uses [CmdletBinding()] with Write-Verbose for optional detailed output
      • Standards: Aligns with PowerShell approved verbs, coding standards, and internal compliance rules
.PARAMETER ActiveCAPoliciesOnly
    Only include policies whose State is Enabled.
.PARAMETER DisabledCAPoliciesOnly
    Only include policies whose State is Disabled.
.PARAMETER ReportOnlyMode
    Only include policies in report-only mode.
.PARAMETER RecentlyCreatedCAPolicies
    Include only policies created within the past N days.
.PARAMETER RecentlyModifiedCAPolicies
    Include only policies modified within the past N days.
.PARAMETER CreateSession
    Force disconnection and re-authentication to Microsoft Graph.
.PARAMETER TenantId
    Directory (tenant) ID for Graph auth (used with ClientId and CertificateThumbprint).
.PARAMETER ClientId
    Application (client) ID for certificate-based Graph auth.
.PARAMETER CertificateThumbprint
    Thumbprint of the certificate used for app-only authentication.
.PARAMETER OutputDirectory
    Directory path for the generated CSV file. Default: "$PSScriptRoot\Output"
.PARAMETER OutputFileName
    File name for the output. Default: "CA_Policies_Report_<timestamp>.csv"
.PARAMETER IncludeEmptyColumns
    Switch to include columns that are empty across all results.
.PARAMETER Verbose
    Enables detailed console output using Write-Verbose. Available because the script uses [CmdletBinding()].
    Use -Verbose to turn on; default is off.
.EXAMPLE
    .\Export-EntraCAPoliciesReport.ps1
    Exports all CA policies with default settings and minimal console output.
.EXAMPLE
    .\Export-EntraCAPoliciesReport.ps1 -ReportOnlyMode -Verbose
    Exports only report-only policies and emits detailed progress and status messages.
.EXAMPLE
    .\Export-EntraCAPoliciesReport.ps1 -OutputDirectory 'D:\Reports' -OutputFileName 'CA_Policies.csv' -IncludeEmptyColumns
    Exports to a custom path and includes columns that are empty across all rows.
.NOTES
    Author: Travis McDade
    Last Updated: 08/08/2025
    Version: 1.0.0
    Original Source:
        Author: Kashyap Patel
        URL   : https://github.com/RapidScripter/export-conditional-access-policies
Revision History:
    1.0.0 – 08/08/2025 – Production-ready version with CmdletBinding(), Write-Verbose conversion,
                         module enforcement, property name corrections, improved progress handling,
                         and Graph session cleanup.
    0.4.0 – 08/08/2025 – Refactor for efficiency, object creation, join-logic, header handling
    0.3.0 – 08/07/2025 – Column pruning and ordered header logic
    0.2.0 – 08/06/2025 – Progress integration and parameter enhancements
    0.1.0 – 06/30/2024 – Initial version from upstream
#>

#Requires -Version 7.2

#region Parameters
[CmdletBinding()]
param
(
    [switch]$ActiveCAPoliciesOnly,
    [switch]$DisabledCAPoliciesOnly,
    [switch]$ReportOnlyMode,
    [int]$RecentlyCreatedCAPolicies,
    [int]$RecentlyModifiedCAPolicies,
    [switch]$CreateSession,
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint,
    [string]$OutputDirectory = "$PSScriptRoot\Output",
    [string]$OutputFileName = "CA_Policies_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [switch]$IncludeEmptyColumns
)

#endregion

#region Module Loading
$RequiredModules = @('Microsoft.Graph.Beta')

foreach ($mod in $RequiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Host "Module '$mod' not found. Installing..." -ForegroundColor Yellow
        Install-Module -Name $mod -Scope CurrentUser -Force -ErrorAction Stop -Confirm:$false
    } else {
        Write-Verbose "Module '$mod' is already installed and available."
    }
}

# Explicitly import only required submodules to avoid lazy-load assembly conflicts
$RequiredSubmodules = @(
    'Microsoft.Graph.Beta.Applications',
    'Microsoft.Graph.Beta.Identity.SignIns'
)

foreach ($sub in $RequiredSubmodules) {
    try {
        Import-Module -Name $sub -ErrorAction Stop
    } catch {
        Write-Error ("Failed to import Graph submodule {0}: {1}" -f $sub, $_.Exception.Message)
        exit 1
    }
}

#endregion

#region Global Hash Caches
$script:DirectoryObjsHash = @{}
$script:ServicePrincipalsHash = @{}
$script:NamedLocationHash = @{}

#endregion

#region Graph Connection
# Authenticates to Microsoft Graph using either certificate-based or interactive login
function Connect-MgGraphSession {
    if ($CreateSession.IsPresent) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
    }

    Write-Verbose "Connecting to Microsoft Graph..."

    if ($TenantId -and $ClientId -and $CertificateThumbprint) {
        Connect-MgGraph -TenantId $TenantId -AppId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome
    } else {
        Connect-MgGraph -Scopes 'Policy.Read.All', 'Directory.Read.All', 'Application.Read.All' -NoWelcome
    }
}

Connect-MgGraphSession

#endregion

#region Conversion Helpers
# Functions to convert raw GUIDs into human-readable names (directory objects, SPNs, named locations)
function ConvertTo-DirectoryObjectName {
    param(
        [Parameter(Mandatory = $true)]
        [Array]$InputIds
    )
    $ConvertedNames = @()

    # Process each value in the array
    foreach ($Id in $InputIds) {
        # Check Id-Name pair already exist in hash table
        if ($DirectoryObjsHash.ContainsKey($Id)) {
            $Name = $DirectoryObjsHash[$Id]
            $ConvertedNames += $Name
        }
        # Retrieve the display name for the directory object with the given ID
        else {
            try {
                $Name = ((Get-MgBetaDirectoryObject -DirectoryObjectId $Id ).AdditionalProperties["displayName"] )
                if ($null -ne $Name) {
                    $DirectoryObjsHash[$Id] = $Name
                    $ConvertedNames += $Name

                }
            } catch {
                Write-Host "Deleted object configured in the CA policy $DisplayName" -ForegroundColor Red
                Write-Host "Continuing to next policy..." -ForegroundColor Gray
            }
        }
    }
    return $ConvertedNames
}

function Get-ServicePrincipalDisplayName {
    param(
        [Parameter(Mandatory = $true)]
        [Array]$InputIds
    )
    $ConvertedNames = @()
    # Process each value in the array
    foreach ($Id in $InputIds) {
        # Check Id-Name pair already exist in hash table
        if ($ServicePrincipalsHash.ContainsKey($Id)) {
            $Name = $ServicePrincipalsHash[$Id].DisplayName
        } else
        { $Name = $Id }
        $ConvertedNames += $Name
    }
    return $ConvertedNames
}

function Get-NamedLocationDisplayName {
    param(
        [Parameter(Mandatory = $true)]
        [Array]$InputIds
    )
    $ConvertedNames = @()
    # Process each value in the array
    foreach ($Id in $InputIds) {
        # Check Id-Name pair already exist in hash table
        if ($NamedLocationHash.ContainsKey($Id)) {
            $Name = $NamedLocationHash[$Id].DisplayName
        } else
        { $Name = $Id }
        $ConvertedNames += $Name
    }
    return $ConvertedNames
}

#endregion

#region Utility Functions
# Miscellaneous helpers to support consistent formatting and data handling
function Join-Array {
    param ([array]$Values)
    return ($Values -join ',')
}

function Export-CaPolicyReport {
    param (
        [array]$Results,
        [string[]]$Headers,
        [string]$Path,
        [switch]$IncludeEmptyColumns
    )

    if (-not $IncludeEmptyColumns) {
        $nonEmptyProps = @()
        $allProps = $Results[0].PSObject.Properties.Name
        foreach ($prop in $allProps) {
            foreach ($row in $Results) {
                $val = $row.PSObject.Properties[$prop].Value
                if ($null -ne $val -and $val -ne '' -and $val -ne ' ') {
                    $nonEmptyProps += $prop
                    break
                }
            }
        }
        $Results | Sort-Object 'DisplayName' | Select-Object -Property ($Headers | Where-Object { $nonEmptyProps -contains $_ }) | Export-Csv -Path $Path -NoTypeInformation
    } else {
        $Results | Sort-Object 'DisplayName' | Select-Object -Property $Headers | Export-Csv -Path $Path -NoTypeInformation
    }
    Write-Progress -Activity "Exporting Conditional Access Policies" -Completed
}

#endregion

#region Prep and Output Path Setup
#Prep
if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}
$ExportCSV = Join-Path -Path $OutputDirectory -ChildPath $OutputFileName
$Results = @()

#endregion

#region Service Principal and Location Lookup
$ProcessedCount = 0
$OutputCount = 0
#Get all service principals
Write-Progress -Activity "Initializing" -Status "Retrieving service principals..." -PercentComplete 10
$ServicePrincipalsHash = Get-MgBetaServicePrincipal -All | Group-Object -Property AppId -AsHashTable
Write-Progress -Activity "Initializing" -Status "Retrieving named locations..." -PercentComplete 20
$NamedLocationHash = Get-MgBetaIdentityConditionalAccessNamedLocation -All | Group-Object -Property Id -AsHashTable
Write-Progress -Activity "Exporting" -Status "Retrieving CA policies..." -PercentComplete 30


#endregion

#region Policy Retrieval and Processing
# Miscellaneous helpers to support consistent formatting and data handling
#Processing all CA policies
$AllPolicies = Get-MgBetaIdentityConditionalAccessPolicy -All
$total = $AllPolicies.Count
$AllPolicies | ForEach-Object {
    $ProcessedCount++
    $DisplayName = $_.DisplayName
    $Description = $_.Description
    $CreatedDateTime = $_.CreatedDateTime
    $ModifiedDateTime = $_.ModifiedDateTime
    $State = $_.State

    # Show progress bar for current policy being processed
    $percent = if ($total -gt 0) { [math]::Round(($ProcessedCount / $total) * 100) } else { 100 }
    Write-Progress -Activity "Exporting Conditional Access Policies" -Status "Processing: $DisplayName" -PercentComplete $percent

    #Filter CA policies based on their State
    if ($ActiveCAPoliciesOnly.IsPresent -and $State -ne "Enabled") {
        return
    } elseif ($DisabledCAPoliciesOnly.IsPresent -and $State -ne "Disabled" ) {
        return
    } elseif ($ReportOnlyMode.IsPresent -and $State -ne "EnabledForReportingButNotEnforced") {
        return
    }

    #Calculating recently created and modified days
    if ($null -eq $CreatedDateTime) {
        $CreatedDateTime = "-"
    } else {
        $CreatedInDays = (New-TimeSpan -Start $CreatedDateTime).Days
    }

    if ($null -eq $ModifiedDateTime) {
        $ModifiedDateTime = "-"
    } else {
        $ModifiedInDays = (New-TimeSpan -Start $ModifiedDateTime).Days
    }

    #Filter for recently created CA policies
    if (($RecentlyCreatedCAPolicies -ne "") -and (($RecentlyCreatedCAPolicies -lt $CreatedInDays) -or ($CreatedDateTime -eq "-"))) {
        return
    }

    #Filter for recently modified CA polcies
    if (($RecentlyModifiedCAPolicies -ne "") -and (($RecentlyModifiedCAPolicies -lt $ModifiedInDays) -or ($ModifiedDateTime -eq "-") )) {
        return
    }

    # --- Assignments Block ---
    # Evaluate and convert all user/group/role assignments from object IDs to display names
    $Conditions = $_.Conditions
    $IncludeUsers = $Conditions.Users.IncludeUsers
    $ExcludeUsers = $Conditions.Users.ExcludeUsers
    $IncludeGroups = $Conditions.Users.IncludeGroups
    $ExcludeGroups = $Conditions.Users.ExcludeGroups
    $IncludeRoles = $Conditions.Users.IncludeRoles
    $ExcludeRoles = $Conditions.Users.ExcludeRoles
    $IncludeGuestsOrExtUsers = $Conditions.Users.IncludeGuestsOrExternalUsers.GuestOrExternalUserTypes
    $ExcludeGuestsOrExtUsers = $Conditions.Users.ExcludeGuestsOrExternalUsers.GuestOrExternalUserTypes

    #Convert id to names for Assignment properties
    if ($IncludeUsers.Count -ne 0 -and ($IncludeUsers -ne 'All' -and $IncludeUsers -ne 'None' )) {
        $IncludeUsers = ConvertTo-DirectoryObjectName -InputIds $IncludeUsers
    }
    $IncludeUsers = Join-Array $IncludeUsers

    if (($ExcludeUsers.Count -ne 0) -and ($ExcludeUsers -ne 'GuestsOrExternalUsers'  )) {
        $ExcludeUsers = ConvertTo-DirectoryObjectName -InputIds $ExcludeUsers
    }
    $ExcludeUsers = Join-Array $ExcludeUsers
    if ($IncludeGroups.Count -ne 0) {
        $IncludeGroups = ConvertTo-DirectoryObjectName -InputIds $IncludeGroups
    }
    $IncludeGroups = Join-Array $IncludeGroups
    if ($ExcludeGroups.Count -ne 0) {
        $ExcludeGroups = ConvertTo-DirectoryObjectName -InputIds $ExcludeGroups
    }
    $ExcludeGroups = Join-Array $ExcludeGroups
    if ($IncludeRoles.Count -ne 0 -and ($IncludeRoles -ne 'All' -and $IncludeRoles -ne 'None' )) {
        $IncludeRoles = ConvertTo-DirectoryObjectName -InputIds $IncludeRoles
    }
    $IncludeRoles = Join-Array $IncludeRoles
    if ($ExcludeRoles.Count -ne 0) {
        $ExcludeRoles = ConvertTo-DirectoryObjectName -InputIds $ExcludeRoles
    }
    $ExcludeRoles = Join-Array $ExcludeRoles

    $IncludeGuestsOrExtUsers = Join-Array $IncludeGuestsOrExtUsers
    $ExcludeGuestsOrExtUsers = Join-Array $ExcludeGuestsOrExtUsers

    # --- Target Resources Block ---
    # Evaluate application and user action conditions
    $IncludeApplications = $_.Conditions.Applications.IncludeApplications
    $ExcludeApplications = $_.Conditions.Applications.ExcludeApplications
    $UserAction = $_.Conditions.Applications.IncludeUserActions
    $UserAction = Join-Array $UserAction

    #Convert id to names for Target resource properties
    if ($IncludeApplications.Count -ne 0 -and ($IncludeApplications -ne 'All' -and $IncludeApplications -ne 'None' )) {
        $IncludeApplications = Get-ServicePrincipalDisplayName -InputIds $IncludeApplications
    }
    $IncludeApplications = Join-Array $IncludeApplications
    if ($ExcludeApplications.Count -ne 0) {
        $ExcludeApplications = Get-ServicePrincipalDisplayName -InputIds $ExcludeApplications
    }
    $ExcludeApplications = Join-Array $ExcludeApplications

    # --- Conditions Block ---
    # Evaluate risk levels, client apps, platforms, and locations
    $UserRiskLevel = $_.Conditions.UserRiskLevels
    $SigninRiskLevel = $_.Conditions.SignInRiskLevels
    $ClientAppTypes = $_.Conditions.ClientAppTypes
    $IncludeDevicePlatform = $_.Conditions.Platforms.IncludePlatforms
    $ExcludeDevicePlatform = $_.Conditions.Platforms.ExcludePlatforms
    $IncludeLocations = $_.Conditions.Locations.IncludeLocations
    $ExcludeLocations = $_.Conditions.Locations.ExcludeLocations

    $UserRiskLevel = Join-Array $UserRiskLevel
    $SigninRiskLevel = Join-Array $SigninRiskLevel
    $ClientAppTypes = Join-Array $ClientAppTypes
    $IncludeDevicePlatform = Join-Array $IncludeDevicePlatform
    $ExcludeDevicePlatform = Join-Array $ExcludeDevicePlatform

    #Convert location id to Name
    if ($IncludeLocations.Count -ne 0 -and $IncludeLocations -ne 'All' -and $IncludeLocations -ne 'AllTrusted') {
        $IncludeLocations = Get-NamedLocationDisplayName -InputIds $IncludeLocations
    }
    $IncludeLocations = Join-Array $IncludeLocations

    if ($ExcludeLocations.Count -ne 0) {
        $ExcludeLocations = Get-NamedLocationDisplayName -InputIds $ExcludeLocations
    }
    $ExcludeLocations = Join-Array $ExcludeLocations

    # --- Grant Controls Block ---
    # Evaluate grant control settings and operator
    $GrantControls = Join-Array $_.GrantControls.BuiltInControls
    $GrantControlsOperator = $_.GrantControls.Operator
    $GrantControlsAuthStrength = $_.GrantControls.AuthenticationStrength.DisplayName

    # --- Session Controls Block ---
    # Evaluate session controls like app restrictions and sign-in frequency
    $AppEnforcedRestrictions = $_.SessionControls.ApplicationEnforcedRestrictions.IsEnabled
    $CloudAppSecurity = $_.SessionControls.CloudAppSecurity.IsEnabled
    $CAEMode = $_.SessionControls.ContinuousAccessEvaluation.Mode
    $DisableResilienceDefaults = $_.SessionControls.DisableResilienceDefaults
    $SigninFrequencyEnabled = $_.SessionControls.SignInFrequency.IsEnabled
    if ($SigninFrequencyEnabled) {
        $Value = $_.SessionControls.SignInFrequency.Value
        $Type = $_.SessionControls.SignInFrequency.Type

        if ($null -eq $Value -and $null -eq $Type) {
            $SignInFrequencyValue = "Every time"
        } else {
            $SignInFrequencyValue = "$Value $Type"
        }
    } else {
        $SignInFrequencyValue = ""
    }

    $OutputCount++
    $Result = @{'DisplayName'                    = $DisplayName;
        'Description'                            = $Description;
        'Created Date Time'                      = $CreatedDateTime;
        'Modified Date Time'                     = $ModifiedDateTime;
        'Include Users'                          = $IncludeUsers;
        'Exclude Users'                          = $ExcludeUsers;
        'Include Groups'                         = $IncludeGroups;
        'Exclude Groups'                         = $ExcludeGroups;
        'Include Roles'                          = $IncludeRoles;
        'Exclude Roles'                          = $ExcludeRoles;
        'Include Guests or External Users'       = $IncludeGuestsOrExtUsers;
        'Exclude Guests or External Users'       = $ExcludeGuestsOrExtUsers;
        'Include Applications'                   = $IncludeApplications;
        'Exclude Applications'                   = $ExcludeApplications;
        'User Action'                            = $UserAction;
        'User Risk Level'                        = $UserRiskLevel;
        'Signin Risk Level'                      = $SigninRiskLevel;
        'Client App Types'                       = $ClientAppTypes;
        'Include Device Platform'                = $IncludeDevicePlatform;
        'Exclude Device Platform'                = $ExcludeDevicePlatform;
        'Include Locations'                      = $IncludeLocations;
        'Exclude Locations'                      = $ExcludeLocations;
        'Grant Controls'                         = $GrantControls;
        'Grant Controls Operator'                = $GrantControlsOperator;
        'Grant Controls Authentication Strength' = $GrantControlsAuthStrength;
        'App Enforced Restrictions Enabled'      = $AppEnforcedRestrictions;
        'Cloud App Security'                     = $CloudAppSecurity;
        'CAE Mode'                               = $CAEMode;
        'Disable Resilience Defaults'            = $DisableResilienceDefaults;
        'Signin Frequency Enabled'               = $SigninFrequencyEnabled;
        'Signin Frequency Value'                 = $SignInFrequencyValue;
        'State'                                  = $State
    }
    $Results += [pscustomobject]$Result
}

#endregion

#region Final Output and Export
# Define export column order (must match keys in $Result)
$orderedHeaders = @(
    'DisplayName', 'Description', 'State', 'Include Users', 'Exclude Users', 'Include Groups', 'Exclude Groups', 'Include Roles', 'Exclude Roles', 'Include Guests or External Users', 'Exclude Guests or External Users', 'Include Applications', 'Exclude Applications', 'User Action', 'User Risk Level', 'Signin Risk Level', 'Client App Types', 'Include Device Platform', 'Exclude Device Platform', 'Include Locations', 'Exclude Locations', 'Grant Controls', 'Grant Controls Operator', 'Grant Controls Authentication Strength', 'App Enforced Restrictions Enabled', 'Cloud App Security', 'CAE Mode', 'Disable Resilience Defaults', 'Signin Frequency Enabled', 'Signin Frequency Value', 'Created Date Time', 'Modified Date Time'
)

# Finalize and export the filtered policy data to CSV, optionally pruning empty columns
if ($Results.Count -eq 0) {
    Write-Warning "No data found for the given criteria."
} else {
    Export-CaPolicyReport -Results $Results -Headers $orderedHeaders -Path $ExportCSV -IncludeEmptyColumns:$IncludeEmptyColumns

    Write-Verbose "The output file contains $($Results.Count) CA policies."
    if ((Test-Path -Path $ExportCSV) -eq $true) {
        Write-Verbose "The output file is available at: $ExportCSV"
        Write-Host $ExportCSV
    }
    # Clean up Microsoft Graph session
    Write-Verbose "Disconnecting from Microsoft Graph..."
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
