<#
.SYNOPSIS
    Export Microsoft Entra ID (Azure AD) Conditional Access (CA) policies—with 33
    detailed attributes—to a timestamped CSV file for audit, compliance, and reporting.
.DESCRIPTION
    This script connects to Microsoft Graph (beta) and exports Conditional Access
    policies in your tenant into a single CSV. Out-of-the-box it supports:
      • Six report types covering 33 attributes for deep policy analysis
      • All policies (default), Active (enabled), Disabled, Report-only mode
      • Time-based filters: recently created or modified policies
      • Interactive MFA or certificate-based authentication
      • Automatic installation of the Graph Beta module if missing
      • Scheduler-friendly, non-GUI operation with optional “open file” prompt
.PARAMETER ActiveCAPoliciesOnly
    Switch – export only policies whose **State** is *Enabled*.
.PARAMETER DisabledCAPoliciesOnly
    Switch – export only policies whose **State** is *Disabled*.
.PARAMETER ReportOnlyMode
    Switch – export only policies whose **State** is *EnabledForReportingButNotEnforced*.
.PARAMETER RecentlyCreatedCAPolicies
    Integer – include only those policies created in the past *N* days.
.PARAMETER RecentlyModifiedCAPolicies
    Integer – include only those policies modified in the past *N* days.
.PARAMETER CreateSession
    Switch – disconnect any existing Microsoft Graph session before reconnecting.
.PARAMETER TenantId
    String – Azure AD tenant GUID (required for certificate-based/app-only auth).
.PARAMETER ClientId
    String – Application (client) ID for certificate-based authentication.
.PARAMETER CertificateThumbprint
    String – Thumbprint of the certificate associated with the ClientId.
.NOTES
    Author: Travis McDade
    Date: 08/08/2025
    Version: 0.2.0
    Original Source
        Author : RapidScripter
        URL    : https://github.com/RapidScripter/export-conditional-access-policies
        Script : Export-CAPolicies.ps1
Revision History:
      0.2.0 – 08/08/2025 – Initial adaptation and add attribution.
      0.1.0 – 06/30/2024 – Upstream version by RapidScripter.
Future Enhancements:
      - None
Known Issues:
      - None
Resources:
      - None
#>

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
    [string]$CertificateThumbprint
)

$RequiredModules = @('Microsoft.Graph.Beta')

foreach ($mod in $RequiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Host "Module '$mod' not found. Installing..." -ForegroundColor Yellow
        Install-Module -Name $mod -Scope CurrentUser -Force -ErrorAction Stop -Confirm:$false
    } else {
        Write-Host "Module '$mod' is already available."
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



$global:DirectoryObjsHash = @{}
$global:ServicePrincipalsHash = @{}
$global:NamedLocationHash = @{}

function Initialize-MgGraphConnection {
    if ($CreateSession.IsPresent) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
    }

    Write-Host "Connecting to Microsoft Graph..."

    if ($TenantId -and $ClientId -and $CertificateThumbprint) {
        Connect-MgGraph -TenantId $TenantId -AppId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome
    } else {
        Connect-MgGraph -Scopes 'Policy.Read.All', 'Directory.Read.All', 'Application.Read.All' -NoWelcome
    }
}

Initialize-MgGraphConnection

function ConvertTo-Name {
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
                Write-Host "Deleted object configured in the CA policy $CAName" -ForegroundColor Red
                Write-Host "Processing CA policies..."
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

#Prep
$Location = Get-Location
$ExportCSV = "$Location\CA_Policies_Report_$((Get-Date -Format yyyy-MMM-dd-ddd` hh-mm` tt).ToString()).csv"
$Result = ""
$Results = @()
$ProcessedCount = 0
$OutputCount = 0
#Get all service principals
Write-Progress -Activity "`n     Retrieving service principals..."
$ServicePrincipalsHash = Get-MgBetaServicePrincipal -All | Group-Object -Property AppId -AsHashTable
Write-Progress -Activity "`n     Retrieving named location..."
$NamedLocationHash = Get-MgBetaIdentityConditionalAccessNamedLocation -All | Group-Object -Property Id -AsHashTable
Write-Host "Exporting CA policies report..." -ForegroundColor Cyan


#Processing all CA polcies
Get-MgBetaIdentityConditionalAccessPolicy -All | ForEach-Object {
    $ProcessedCount++
    $CAName = $_.DisplayName
    $Description = $_.Description
    $CreationTime = $_.CreatedDateTime
    $LastModifiedTime = $_.ModifiedDateTime
    $State = $_.State
    Write-Progress -Activity "`n     Processed CA policies count: $ProcessedCount "`n"  Currently Processing: $CAName"

    #Filter CA policies based on their State
    if ($ActiveCAPoliciesOnly.IsPresent -and $State -ne "Enabled") {
        return
    } elseif ($DisabledCAPoliciesOnly.IsPresent -and $State -ne "Disabled" ) {
        return
    } elseif ($ReportOnlyMode.IsPresent -and $State -ne "EnabledForReportingButNotEnforced") {
        return
    }

    #Calculating recently created and modified days
    if ($CreationTime -eq $null) {
        $CreationTime = "-"
    } else {
        $CreatedInDays = (New-TimeSpan -Start $CreationTime).Days
    }

    if ($LastModifiedTime -eq $null) {
        $LastModifiedTime = "-"
    } else {
        $ModifiedInDays = (New-TimeSpan -Start $LastModifiedTime).Days
    }

    #Filter for recently created CA policies
    if (($RecentlyCreatedCAPolicies -ne "") -and (($RecentlyCreatedCAPolicies -lt $CreatedInDays) -or ($CreationTime -eq "-"))) {
        return
    }

    #Filter for recently modified CA polcies
    if (($RecentlyModifiedCAPolicies -ne "") -and (($RecentlyModifiedCAPolicies -lt $ModifiedInDays) -or ($LastModifiedTime -eq "-") )) {
        return
    }


    #Assignments
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
        $IncludeUsers = ConvertTo-Name -InputIds $IncludeUsers
    }
    $IncludeUsers = $IncludeUsers -join ","

    if (($ExcludeUsers.Count -ne 0) -and ($ExcludeUsers -ne 'GuestsOrExternalUsers'  )) {
        $ExcludeUsers = ConvertTo-Name -InputIds $ExcludeUsers
    }
    $ExcludeUsers = $ExcludeUsers -join ","
    if ($IncludeGroups.Count -ne 0) {
        $IncludeGroups = ConvertTo-Name -InputIds $IncludeGroups
    }
    $IncludeGroups = $IncludeGroups -join ","
    if ($ExcludeGroups.Count -ne 0) {
        $ExcludeGroups = ConvertTo-Name -InputIds $ExcludeGroups
    }
    $ExcludeGroups = $ExcludeGroups -join ","
    if ($IncludeRoles.Count -ne 0 -and ($IncludeRoles -ne 'All' -and $IncludeRoles -ne 'None' )) {
        $IncludeRoles = ConvertTo-Name -InputIds $IncludeRoles
    }
    $IncludeRoles = $IncludeRoles -join ","
    if ($ExcludeRoles.Count -ne 0) {
        $ExcludeRoles = ConvertTo-Name -InputIds $ExcludeRoles
    }
    $ExcludeRoles = $ExcludeRoles -join ","

    $IncludeGuestsOrExtUsers = $IncludeGuestsOrExtUsers -join ","
    $ExcludeGuestsOrExtUsers = $ExcludeGuestsOrExtUsers -join ","



    #Target Resources
    $IncludeApplications = $_.Conditions.Applications.IncludeApplications
    $ExcludeApplications = $_.Conditions.Applications.ExcludeApplications
    $UserAction = $_.Conditions.Applications.IncludeUserActions
    $UserAction = $UserAction -join ","

    #Convert id to names for Target resource properties
    if ($IncludeApplications.Count -ne 0 -and ($IncludeApplications -ne 'All' -and $IncludeApplications -ne 'None' )) {
        $IncludeApplications = Get-ServicePrincipalDisplayName -InputIds $IncludeApplications
    }
    $IncludeApplications = $IncludeApplications -join ","
    if ($ExcludeApplications.Count -ne 0) {
        $ExcludeApplications = Get-ServicePrincipalDisplayName -InputIds $ExcludeApplications
    }
    $ExcludeApplications = $ExcludeApplications -join ","



    #Conditions
    $UserRisk = $_.Conditions.UserRiskLevels
    $SigninRisk = $_.Conditions.SignInRiskLevels
    $ClientApps = $_.Conditions.ClientAppTypes
    $IncludeDevicePlatform = $_.Conditions.Platforms.IncludePlatforms
    $ExcludeDevicePlatform = $_.Conditions.Platforms.ExcludePlatforms
    $IncludeLocations = $_.Conditions.Locations.IncludeLocations
    $ExcludeLocations = $_.Conditions.Locations.ExcludeLocations

    $UserRisk = $UserRisk -join ","
    $SigninRisk = $SigninRisk -join ","
    $ClientApps = $ClientApps -join ","
    $IncludeDevicePlatform = $IncludeDevicePlatform -join ","
    $ExcludeDevicePlatform = $ExcludeDevicePlatform -join ","

    #Convert location id to Name
    if ($IncludeLocations.Count -ne 0 -and $IncludeLocations -ne 'All' -and $IncludeLocations -ne 'AllTrusted') {
        $IncludeLocations = Get-NamedLocationDisplayName -InputIds $IncludeLocations
    }
    $IncludeLocations = $IncludeLocations -join ","

    if ($ExcludeLocations.Count -ne 0) {
        $ExcludeLocations = Get-NamedLocationDisplayName -InputIds $ExcludeLocations
    }
    $ExcludeLocations = $ExcludeLocations -join ","



    #Grant Control
    $AccessControl = $_.GrantControls.BuiltInControls -join ","
    $AccessControlOperator = $_.GrantControls.Operator
    $AuthenticationStrength = $_.GrantControls.AuthenticationStrength.DisplayName
    $AuthenticationStrengthAllowedCombo = $_.GrantControls.AuthenticationStrength.AllowedCombinations -join ","

    #Session Control
    $AppEnforcedRestrictions = $_.SessionControls.ApplicationEnforcedRestrictions.IsEnabled
    $CloudAppSecurity = $_.SessionControls.CloudAppSecurity.IsEnabled
    $CAEMode = $_.SessionControls.ContinuousAccessEvaluation.Mode
    $DisableResilienceDefaults = $_.SessionControls.DisableResilienceDefaults
    $IsSigninFrequencyEnabled = $_.SessionControls.SignInFrequency.IsEnabled
    $SignInFrequencyValue = "$($_.SessionControls.SignInFrequency.Value) $($_.SessionControls.SignInFrequency.Type)"



    $OutputCount++
    $Result = @{'CA Policy Name'            = $CAName;
        'Description'                       = $Description;
        'Creation Time'                     = $CreationTime;
        'Modified Time'                     = $LastModifiedTime;
        'Include Users'                     = $IncludeUsers;
        'Exclude Users'                     = $ExcludeUsers;
        'Include Groups'                    = $IncludeGroups;
        'Exclude Groups'                    = $ExcludeGroups;
        'Include Roles'                     = $IncludeRoles;
        'Exclude Roles'                     = $ExcludeRoles;
        'Include Guests or Ext Users'       = $IncludeGuestsOrExtUsers;
        'Exclude Guests or Ext Users'       = $ExcludeGuestsOrExtUsers;
        'Include Applications'              = $IncludeApplications;
        'Exclude Applications'              = $ExcludeApplications;
        'User Action'                       = $UserAction;
        'User Risk'                         = $UserRisk;
        'Signin Risk'                       = $SigninRisk;
        'Client Apps'                       = $ClientApps;
        'Include Device Platform'           = $IncludeDevicePlatform;
        'Exclude Device Platform'           = $ExcludeDevicePlatform;
        'Include Locations'                 = $IncludeLocations;
        'Exclude Locations'                 = $ExcludeLocations;
        'Access Control'                    = $AccessControl;
        'Access Control Operator'           = $AccessControlOperator;
        'Authentication Strength'           = $AuthenticationStrength;
        'Auth Strength Allowed Combo'       = $AuthenticationStrengthAllowedCombo;
        'App Enforced Restrictions Enabled' = $AppEnforcedRestrictions;
        'Cloud App Security'                = $CloudAppSecurity;
        'CAE Mode'                          = $CAEMode;
        'Disable Resilience Defaults'       = $DisableResilienceDefaults;
        'Is Signin Frequency Enabled'       = $IsSigninFrequencyEnabled;
        'Signin Frequency Value'            = $SignInFrequencyValue;
        'State'                             = $State
    }
    $Results = New-Object PSObject -Property $Result
    $Results | Select-Object 'CA Policy Name', 'Description', 'Creation Time', 'Modified Time', 'State', 'Include Users', 'Exclude Users', 'Include Groups', 'Exclude Groups', 'Include Roles', 'Exclude Roles',
    'Include Guests or Ext Users', 'Exclude Guests or Ext Users', 'Include Applications', 'Exclude Applications', 'User Action', 'User Risk', 'Signin Risk', 'Client Apps', 'Include Device Platform',
    'Exclude Device Platform', 'Include Locations', 'Exclude Locations', 'Access Control', 'Access Control Operator', 'Authentication Strength', 'Auth Strength Allowed Combo',
    'App Enforced Restrictions Enabled', 'Cloud App Security', 'CAE Mode', 'Disable Resilience Defaults', 'Is Signin Frequency Enabled', 'Signin Frequency Value' | Export-Csv -Path $ExportCSV -Notype -Append
}


#Open output file after execution
if ($OutputCount -eq 0) {
    Write-Host No data found for the given criteria
} else {
    Write-Host `nThe output file contains $OutputCount CA policies.
    if ((Test-Path -Path $ExportCSV) -eq "True") {
        Write-Host `nThe Output file available in:  -NoNewline -ForegroundColor Yellow
        Write-Host $ExportCSV

        $Prompt = New-Object -ComObject wscript.shell
        $UserInput = $Prompt.popup("Do you want to open output file?", `
                0, "Open Output File", 4)
        if ($UserInput -eq 6) {
            Invoke-Item "$ExportCSV"
        }
    }
}
