#Requires -Version 5.1

<#
.SYNOPSIS
    Create or update Exchange Online transport rule for external email disclaimers
.DESCRIPTION
    Creates or updates a transport rule to prepend security banners to external emails.
    Based on methodology from ArchiTech Labs: https://www.architechlabs.io

    Blog post: https://www.architechlabs.io/articles/external-email-banner/
.PARAMETER OrgPrefix
    Your organization prefix/name for the header (2-50 characters). Spaces will be removed.
    Examples: 'Contoso Corp' becomes 'X-ContosoCorp-Disclaimer-External'
             'ACME Industries' becomes 'X-ACMEIndustries-Disclaimer-External'
             'CONTOSO' becomes 'X-CONTOSO-Disclaimer-External'
.PARAMETER Priority
    Transport rule priority (0 = highest). Default: 0
.PARAMETER RuleName
    Transport rule name. Default: "Security – Inbound External – Prepend Disclaimer"
.PARAMETER Remove
    Remove the transport rule instead of creating/updating it
.PARAMETER Disabled
    Create the rule in disabled state (safer for testing)
.PARAMETER Mode
    Transport rule Mode: Enforce | Audit | AuditAndNotify. Default: Enforce
    - Enforce: Normal operation (applies disclaimer)
    - Audit: Log matching messages without modifying them
    - AuditAndNotify: Log and send incident reports without modifying messages
.PARAMETER AutoInstallModules
    If set, missing required modules will be installed for the current user
.PARAMETER AutoConnect
    If set, automatically connect to Exchange Online if not already connected
.EXAMPLE
    .\New-EXOExternalDisclaimerTransportRule.ps1 -OrgPrefix "Contoso Corp"
.EXAMPLE
    .\New-EXOExternalDisclaimerTransportRule.ps1 -OrgPrefix "ACME" -Priority 2 -WhatIf
.EXAMPLE
    .\New-EXOExternalDisclaimerTransportRule.ps1 -OrgPrefix "MyOrg" -Remove -Confirm
.EXAMPLE
    .\New-EXOExternalDisclaimerTransportRule.ps1 -OrgPrefix "MyOrg" -Disabled
.EXAMPLE
    .\New-EXOExternalDisclaimerTransportRule.ps1 -OrgPrefix "ACME" -AutoInstallModules -AutoConnect
.EXAMPLE
    .\New-EXOExternalDisclaimerTransportRule.ps1 -OrgPrefix "MyOrg" -Mode Audit
.NOTES
    Requires Exchange Online PowerShell connection (Connect-ExchangeOnline)

    Author: Travis McDade
    Organization: ArchiTech Labs
    Website: https://www.architechlabs.io
    Version: 1.1.0

    Based on security methodology developed by ArchiTech Labs.

.LINK
    https://www.architechlabs.io/articles/external-email-banner/

.LINK
    https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules

.LINK
    https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/conditions-and-exceptions
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Your organization prefix/name for the header (2-50 characters, letters/numbers/spaces only)")]
    [ValidateLength(2, 50)]
    [ValidatePattern('^[A-Za-z0-9\s]+$')]
    [ValidateScript({
            $cleaned = $_ -replace '\s+', '' -replace '[^A-Za-z0-9]', ''
            if ($cleaned.Length -lt 2) {
                throw "Organization prefix '$_' becomes '$cleaned' which is too short (minimum 2 characters)."
            }
            if ($cleaned.Length -gt 50) {
                throw "Organization prefix '$_' becomes '$cleaned' which exceeds 50 character limit for headers."
            }
            return $true
        })]
    [Alias("OrganizationName", "OrgName")]
    [string]$OrgPrefix,

    [Parameter(HelpMessage = "Transport rule priority (0 = highest priority)")]
    [ValidateRange(0, 100)]
    [int]$Priority = 0,

    [Parameter(HelpMessage = "Transport rule name")]
    [ValidateNotNullOrEmpty()]
    [string]$RuleName = "Security – Inbound External – Prepend Disclaimer",

    [Parameter(HelpMessage = "Remove the transport rule instead of creating/updating it")]
    [switch]$Remove,

    [Parameter(HelpMessage = "Create the rule in disabled state (safer for testing)")]
    [switch]$Disabled,

    [Parameter(HelpMessage = "If set, missing required modules will be installed for the current user")]
    [switch]$AutoInstallModules,

    [Parameter(HelpMessage = "If set, automatically connect to Exchange Online if not already connected")]
    [switch]$AutoConnect,

    [Parameter(HelpMessage = "Transport rule Mode: Enforce | Audit | AuditAndNotify")]
    [ValidateSet('Enforce', 'Audit', 'AuditAndNotify')]
    [string]$Mode = 'Enforce'
)

# Convert organization prefix to header-safe format
$HeaderSafePrefix = $OrgPrefix -replace '\s+', '' -replace '[^A-Za-z0-9]', ''
$HeaderName = "X-$HeaderSafePrefix-Disclaimer-External"
$HeaderValue = "Applied"

#region Functions

function Install-RequiredModules {
    [CmdletBinding()]
    param([string[]]$ModuleNames)

    foreach ($Module in $ModuleNames) {
        if (-not (Get-Module -ListAvailable -Name $Module)) {
            if ($AutoInstallModules) {
                Write-Information "Installing required module: $Module" -InformationAction Continue
                try {
                    Install-Module -Name $Module -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
                    Write-Information "Successfully installed $Module" -InformationAction Continue
                } catch {
                    throw "Failed to install required module '$Module': $($_.Exception.Message)"
                }
            } else {
                throw "Required module '$Module' is not installed. Rerun with -AutoInstallModules or install manually: Install-Module -Name $Module"
            }
        }
    }
}

function Test-ExchangeOnlineConnection {
    [CmdletBinding()]
    param()

    try {
        Get-OrganizationConfig -ErrorAction Stop | Out-Null
        Write-Verbose "Connected to Exchange Online"
        return $true
    } catch {
        if ($AutoConnect) {
            Write-Information "Not connected to Exchange Online. Attempting to connect..." -InformationAction Continue
            try {
                Connect-ExchangeOnline -ErrorAction Stop
                Write-Information "Successfully connected to Exchange Online" -InformationAction Continue
                return $true
            } catch {
                throw "Failed to connect to Exchange Online automatically: $($_.Exception.Message). Try running Connect-ExchangeOnline manually."
            }
        } else {
            throw "Not connected to Exchange Online. Run Connect-ExchangeOnline first, or use -AutoConnect to connect automatically."
        }
    }
}

function Write-ScriptBanner {
    [CmdletBinding()]
    param(
        [string]$OrgPrefix,
        [string]$HeaderName,
        [string]$RuleName,
        [int]$Priority,
        [string]$Mode,
        [switch]$Remove,
        [switch]$Disabled
    )

    if ($Remove) {
        Write-Information "MODE: Remove Rule" -InformationAction Continue
    } else {
        Write-Information "MODE: Deploy/Update Rule" -InformationAction Continue
    }

    Write-Information "Organization: $OrgPrefix" -InformationAction Continue
    Write-Information "Header Name: $HeaderName" -InformationAction Continue
    Write-Information "Rule Name: $RuleName" -InformationAction Continue
    Write-Information "Priority: $Priority" -InformationAction Continue
    Write-Information "Rule State: $(if ($Disabled -and -not $Remove) { 'Disabled' } else { 'Enabled' })" -InformationAction Continue
    Write-Information "Mode: $Mode" -InformationAction Continue

    $HeaderSafePrefix = $OrgPrefix -replace '\s+', '' -replace '[^A-Za-z0-9]', ''
    if ($HeaderSafePrefix -match '^ATL$|^ATL') {
        Write-Warning "Note: 'ATL' is ArchiTech Labs' prefix - consider using your org's name for clarity"
    }

    if (-not $Remove) {
        Write-Information "Duplicate Prevention: Enabled (via $HeaderName header)" -InformationAction Continue
        if ($Disabled) {
            Write-Warning "Rule will be created in DISABLED state for safe testing"
        }
        if ($Mode -ne 'Enforce') {
            Write-Information "Progressive Enforcement: Rule will run in $Mode mode (safer for initial rollout)" -InformationAction Continue
        }
    }
}

function Remove-ExternalDisclaimerRule {
    [CmdletBinding()]
    param([string]$RuleName)

    $existing = Get-TransportRule -Identity $RuleName -ErrorAction SilentlyContinue

    if ($existing) {
        Remove-TransportRule -Identity $RuleName -Confirm:$false -ErrorAction Stop
        Write-Information "Successfully removed transport rule: $RuleName" -InformationAction Continue
    } else {
        Write-Warning "Transport rule '$RuleName' does not exist - nothing to remove"
    }
}

function New-ExternalDisclaimerRule {
    [CmdletBinding()]
    param(
        [string]$RuleName,
        [int]$Priority,
        [string]$HeaderName,
        [string]$HeaderValue,
        [string]$BannerHtml,
        [string]$Mode,
        [switch]$Disabled
    )

    $existing = Get-TransportRule -Identity $RuleName -ErrorAction SilentlyContinue

    $ruleParams = @{
        Comments                           = "External email disclaimer per ArchiTech Labs methodology (https://www.architechlabs.io). Prevents duplicates via header stamp. Blog: https://www.architechlabs.io/articles/external-email-banner/"
        Priority                           = $Priority
        FromScope                          = 'NotInOrganization'
        SentToScope                        = 'InOrganization'
        ApplyHtmlDisclaimerLocation        = 'Prepend'
        ApplyHtmlDisclaimerText            = $BannerHtml
        ApplyHtmlDisclaimerFallbackAction  = 'Wrap'
        SetHeaderName                      = $HeaderName
        SetHeaderValue                     = $HeaderValue
        ExceptIfHeaderMatchesMessageHeader = $HeaderName
        ExceptIfHeaderMatchesPatterns      = $HeaderValue
        Enabled                            = -not $Disabled
        Mode                               = $Mode
    }

    if (-not $existing) {
        Write-Information "Creating transport rule: $RuleName" -InformationAction Continue
        New-TransportRule -Name $RuleName @ruleParams -ErrorAction Stop
        $stateMsg = if ($Disabled) { " (DISABLED)" } else { " (ENABLED)" }
        Write-Information "Successfully created transport rule: $RuleName$stateMsg | Mode: $Mode" -InformationAction Continue
    } else {
        Write-Information "Updating existing transport rule: $RuleName" -InformationAction Continue
        Set-TransportRule -Identity $RuleName @ruleParams -ErrorAction Stop
        $stateMsg = if ($Disabled) { " (DISABLED)" } else { " (ENABLED)" }
        Write-Information "Successfully updated transport rule: $RuleName$stateMsg | Mode: $Mode" -InformationAction Continue
    }
}

#endregion Functions

# Install required modules and verify connection
Install-RequiredModules -ModuleNames @('ExchangeOnlineManagement')
Test-ExchangeOnlineConnection

# Display configuration banner
Write-ScriptBanner -OrgPrefix $OrgPrefix -HeaderName $HeaderName -RuleName $RuleName -Priority $Priority -Mode $Mode -Remove:$Remove -Disabled:$Disabled

# Banner HTML content (using single-quoted here-string to prevent variable expansion)
$BannerHtml = @'
<table role="presentation" width="100%" border="0" cellspacing="0" cellpadding="0" style="mso-table-lspace:0;mso-table-rspace:0;">
  <tr>
    <td align="left" style="mso-table-lspace:0;mso-table-rspace:0;">
      <table role="presentation" border="0" cellspacing="0" cellpadding="0" width="760" style="width:100%;max-width:760px;mso-table-lspace:0;mso-table-rspace:0;">
        <tr>
          <td style="mso-table-lspace:0;mso-table-rspace:0;">
            <div dir="ltr" lang="en" role="note" aria-label="External email warning"
                 style="-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%;-moz-text-size-adjust:100%;
                        mso-line-height-rule:exactly;border:2px solid #d79c2b;
                        padding:8px;background:transparent;color:inherit;
                        font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:1.5;">
              <strong>⚠️ External Email – Check Before You&nbsp;Act</strong><br><br>
              This email is from <strong>outside our&nbsp;organization</strong>.<br>
              • Do not reply, click links, or open attachments unless you trust the&nbsp;sender.<br>
              • If it looks like it came from someone inside, confirm another way before acting.<br>
              • Report suspicious messages using the <strong>REPORT</strong>&nbsp;button.
            </div>
            <div style="line-height:0;font-size:0;" aria-hidden="true">
              <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="mso-table-lspace:0;mso-table-rspace:0;">
                <tr><td style="height:8px;line-height:8px;font-size:8px;">&nbsp;</td></tr>
              </table>
            </div>
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>
'@

# Handle operations based on parameters
try {
    if ($Remove) {
        if ($PSCmdlet.ShouldProcess($RuleName, "Remove transport rule")) {
            Remove-ExternalDisclaimerRule -RuleName $RuleName
        }
    } else {
        if ($PSCmdlet.ShouldProcess($RuleName, "Create/update transport rule")) {
            New-ExternalDisclaimerRule -RuleName $RuleName -Priority $Priority -HeaderName $HeaderName -HeaderValue $HeaderValue -BannerHtml $BannerHtml -Mode $Mode -Disabled:$Disabled
        }
    }

    # Display completion message
    if (-not $Remove) {
        Write-Information "Configuration complete!" -InformationAction Continue
        if ($Disabled) {
            Write-Warning "The rule '$RuleName' is created but DISABLED. Enable it when ready to activate."
            Write-Information "To enable: Set-TransportRule -Identity '$RuleName' -Enabled `$true" -InformationAction Continue
        } else {
            Write-Information "The rule '$RuleName' is now active with NO authentication exceptions." -InformationAction Continue
        }
    }
} catch {
    Write-Error "Failed to configure transport rule: $($_.Exception.Message)"
    Write-Warning "Common issues: Insufficient Exchange Online permissions, network connectivity, rule name conflicts, or transport rule size limits"
    throw
}
