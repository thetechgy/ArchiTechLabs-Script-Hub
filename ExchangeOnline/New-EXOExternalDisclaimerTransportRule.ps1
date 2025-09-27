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
.PARAMETER Disabled
    Create the rule in disabled state (safer for testing)
.EXAMPLE
    .\New-EXOExternalDisclaimerTransportRule.ps1 -OrgPrefix "Contoso Corp"
.EXAMPLE
    .\New-EXOExternalDisclaimerTransportRule.ps1 -OrgPrefix "ACME" -Priority 2 -WhatIf
.EXAMPLE
    .\New-EXOExternalDisclaimerTransportRule.ps1 -OrgPrefix "MyOrg" -Disabled
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
            if ($cleaned.Length -lt 2 -or $cleaned.Length -gt 50) {
                throw "Organization prefix results in '$cleaned' which must be 2-50 characters after cleanup."
            }
            $true
        })]
    [string]$OrgPrefix,

    [Parameter(HelpMessage = "Transport rule priority (0 = highest priority)")]
    [ValidateRange(0, 100)]
    [int]$Priority = 0,

    [Parameter(HelpMessage = "Transport rule name")]
    [ValidateNotNullOrEmpty()]
    [string]$RuleName = "Security – Inbound External – Prepend Disclaimer",

    [Parameter(HelpMessage = "Create the rule in disabled state (safer for testing)")]
    [switch]$Disabled
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
            Write-Information "Installing required module: $Module" -InformationAction Continue
            try {
                Install-Module -Name $Module -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
                Write-Information "Successfully installed $Module" -InformationAction Continue
            } catch {
                throw "Failed to install required module '$Module': $($_.Exception.Message). Please run 'Install-Module -Name $Module' manually or ensure you have appropriate permissions."
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
    } catch {
        Write-Information "Not connected to Exchange Online. Attempting to connect..." -InformationAction Continue
        try {
            Connect-ExchangeOnline -ShowProgress:$false -ErrorAction Stop
            Write-Information "Successfully connected to Exchange Online" -InformationAction Continue
        } catch {
            throw "Failed to connect to Exchange Online: $($_.Exception.Message). Please ensure you have the necessary permissions and network connectivity."
        }
    }
}

function Set-ExternalDisclaimerRule {
    [CmdletBinding()]
    param(
        [string]$RuleName,
        [int]$Priority,
        [string]$HeaderName,
        [string]$HeaderValue,
        [string]$BannerHtml,
        [switch]$Disabled
    )

    $existing = Get-TransportRule -Identity $RuleName -ErrorAction SilentlyContinue

    $ruleParams = @{
        Comments                           = "Appends disclaimer on all inbound external mail.`nAdds $HeaderName header to mark processing and prevent dupes.`nExceptions only via auth results (DKIM > SPF > Return-Path).`nFocused on accessibility, consistency, security, and usability."
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
        SenderAddressLocation              = 'Envelope'
    }

    $action = if (-not $existing) { "Creating" } else { "Updating" }
    Write-Information "$action transport rule: $RuleName" -InformationAction Continue

    if (-not $existing) {
        New-TransportRule -Name $RuleName @ruleParams -ErrorAction Stop
    } else {
        Set-TransportRule -Identity $RuleName @ruleParams -ErrorAction Stop
    }

    $stateMsg = if ($Disabled) { " (DISABLED)" } else { " (ENABLED)" }
    Write-Information "Successfully $($action.ToLower()) transport rule: $RuleName$stateMsg" -InformationAction Continue
}

#endregion Functions

# Install required modules and verify connection
Install-RequiredModules -ModuleNames @('ExchangeOnlineManagement')
Test-ExchangeOnlineConnection

# Display configuration
Write-Information "MODE: Deploy/Update Rule" -InformationAction Continue
Write-Information "Organization: $OrgPrefix" -InformationAction Continue
Write-Information "Header Name: $HeaderName" -InformationAction Continue
Write-Information "Rule Name: $RuleName" -InformationAction Continue
Write-Information "Priority: $Priority" -InformationAction Continue
Write-Information "Rule State: $(if ($Disabled) { 'Disabled' } else { 'Enabled' })" -InformationAction Continue
Write-Information "Duplicate Prevention: Enabled (via $HeaderName header)" -InformationAction Continue

if ($Disabled) {
    Write-Warning "Rule will be created in DISABLED state for safe testing"
}

# Banner HTML content (using single-quoted here-string to prevent variable expansion)
$BannerHtml = @'
<table role="presentation" width="100%" border="0" cellspacing="0" cellpadding="0" style="mso-table-lspace:0;mso-table-rspace:0;">
  <tr>
    <td align="left" style="mso-table-lspace:0;mso-table-rspace:0;">
      <!-- Width-capped container for comfortable line length -->
      <table role="presentation" border="0" cellspacing="0" cellpadding="0" width="760" style="width:100%;max-width:760px;mso-table-lspace:0;mso-table-rspace:0;">
        <tr>
          <td style="mso-table-lspace:0;mso-table-rspace:0;">

            <div dir="ltr" lang="en" role="note" aria-label="External email warning"
                 style="-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%;-moz-text-size-adjust:100%;
                        mso-line-height-rule:exactly;border:2px solid #d79c2b;
                        padding:8px;background:transparent;color:inherit;
                        font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:1.5;">
              <strong>⚠️External Email – Verify Before You Act⚠️</strong><br><br>
              This email is from <strong>outside the organization</strong>.<br>
              • Do not reply, click links, or open attachments unless you trust the sender.<br>
              • If it appears to be from someone inside the organization, confirm via another method before taking action.<br>
              • Report suspicious messages using the <strong>Report</strong> button.
            </div>

            <!-- Spacer: consistent gap below the banner in all Outlook clients -->
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

# Deploy the rule
try {
    if ($PSCmdlet.ShouldProcess($RuleName, "Create/update transport rule")) {
        Set-ExternalDisclaimerRule -RuleName $RuleName -Priority $Priority -HeaderName $HeaderName -HeaderValue $HeaderValue -BannerHtml $BannerHtml -Disabled:$Disabled
    }

    # Display completion message
    Write-Information "Configuration complete!" -InformationAction Continue
    if ($Disabled) {
        Write-Warning "The rule '$RuleName' is created but DISABLED. Enable it when ready to activate."
        Write-Information "To enable: Set-TransportRule -Identity '$RuleName' -Enabled `$true" -InformationAction Continue
    } else {
        Write-Information "The rule '$RuleName' is now active with NO authentication exceptions." -InformationAction Continue
    }
} catch {
    Write-Error "Failed to configure transport rule: $($_.Exception.Message)"
    Write-Warning "Common issues: Insufficient Exchange Online permissions, network connectivity, rule name conflicts, or transport rule size limits"
    throw
}
