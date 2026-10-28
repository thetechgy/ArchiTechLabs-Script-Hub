#Requires -Version 7.0

# PSU loads the matching ExternalDisclaimer.psm1 into app endpoint runspaces.
Import-Module (Join-Path $PSScriptRoot 'ExternalDisclaimer.psm1') -ErrorAction Stop

New-UDApp -Title 'ArchiTech Labs | External email banner' -HeaderColor '#ffffff' -HeaderBackgroundColor '#152c42' -Content {
    New-UDElement -Tag 'main' -Attributes @{
        style = @{ maxWidth = '1280px'; margin = '0 auto'; padding = '24px' }
    } -Content {
        New-UDElement -Tag 'p' -Content { 'ARCHITECH LABS / EXCHANGE ONLINE' }
        New-UDElement -Tag 'h1' -Content { 'External email banner' }
        New-UDTypography -Text 'Configure a transport rule, preview the email banner, and review the PowerShell command.' -GutterBottom
        New-UDAlert -Severity 'info' -Text 'Proof of concept | Preview only. This app does not connect to Exchange or create rules.'

        New-UDElement -Tag 'div' -Attributes @{
            style = @{
                display = 'grid'
                gridTemplateColumns = 'repeat(auto-fit, minmax(min(100%, 360px), 1fr))'
                gap = '24px'
                marginTop = '24px'
                alignItems = 'start'
            }
        } -Content {
            New-UDPaper -Width '100%' -Height 'auto' -Style @{ padding = '24px'; boxSizing = 'border-box' } -Children {
                $defaults = $Session:ExternalDisclaimerPreview
                if ($null -eq $defaults) {
                    $defaults = Get-ExternalDisclaimerPreview -OrgPrefix 'Contoso Corp'
                }
                New-UDElement -Tag 'h2' -Content { 'Rule configuration' }
                New-UDForm -Id 'disclaimer-form' -SubmitText 'Update preview' -ButtonVariant 'contained' -Content {
                    New-UDTextbox -Id 'OrgPrefix' -Label 'Organization prefix' -Value $defaults.OrgPrefix -FullWidth -HelperText 'Required: 2-50 letters, numbers, or whitespace; at least two letters or numbers.'
                    New-UDTypography -Text 'Whitespace is removed from the processing header.' -GutterBottom
                    New-UDTextbox -Id 'RuleName' -Label 'Transport rule name' -Value $defaults.RuleName -FullWidth
                    New-UDTextbox -Id 'Priority' -Label 'Priority (0 = highest)' -Type 'number' -Minimum 0 -Maximum 100 -Value $defaults.Priority -FullWidth
                    New-UDSelect -Id 'RuleState' -Label 'Proposed rule state' -DefaultValue $defaults.RuleState -Option {
                        New-UDSelectOption -Name 'Disabled (recommended for testing)' -Value 'Disabled'
                        New-UDSelectOption -Name 'Enabled' -Value 'Enabled'
                    }
                    New-UDTypography -Text 'This selects the proposed state only. Every generated command includes -WhatIf.' -GutterBottom
                } -OnValidate {
                    try {
                        Get-ExternalDisclaimerPreview -OrgPrefix $EventData.OrgPrefix -RuleName $EventData.RuleName -Priority $EventData.Priority -RuleState $EventData.RuleState -ErrorAction Stop | Out-Null
                        New-UDFormValidationResult -Valid
                    }
                    catch {
                        New-UDFormValidationResult -ValidationError $_.Exception.Message
                    }
                } -OnSubmit {
                    try {
                        # Validate again on submit. Data stays in this visitor's session.
                        $Session:ExternalDisclaimerPreview = Get-ExternalDisclaimerPreview -OrgPrefix $EventData.OrgPrefix -RuleName $EventData.RuleName -Priority $EventData.Priority -RuleState $EventData.RuleState -ErrorAction Stop
                        Sync-UDElement -Id 'disclaimer-preview'
                    }
                    catch {
                        Show-UDToast -Message $_.Exception.Message
                    }
                }
            }

            New-UDDynamic -Id 'disclaimer-preview' -Content {
                $preview = $Session:ExternalDisclaimerPreview
                if ($null -eq $preview) {
                    $preview = Get-ExternalDisclaimerPreview -OrgPrefix 'Contoso Corp'
                }
                New-UDPaper -Width '100%' -Height 'auto' -Style @{ padding = '24px'; boxSizing = 'border-box'; minWidth = 0 } -Children {
                    New-UDElement -Tag 'h2' -Content { 'Preview' }
                    New-UDElement -Tag 'div' -Attributes @{ role = 'status'; 'aria-live' = 'polite'; 'aria-atomic' = 'true' } -Content {
                        New-UDTypography -Text "Proposed state: $($preview.RuleState) | Priority: $($preview.Priority)"
                        New-UDTypography -Text "Processing header: $($preview.HeaderName) = Applied" -Style @{ overflowWrap = 'anywhere' }
                    }
                    New-UDElement -Tag 'h3' -Content { 'Example inbound email' }
                    New-UDTypography -Text 'From: Example sender <sender@example.net>'
                    New-UDTypography -Text 'Subject: Document for your review' -GutterBottom
                    # Render only the source banner in a sandboxed frame. Form values
                    # are rendered as text, never interpolated into HTML.
                    $document = '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src ''none''; style-src ''unsafe-inline''"><style>body{margin:8px;color:#172b3a;background:white;font-family:Arial,sans-serif}table{max-width:100%}</style></head><body>' + $preview.BannerHtml + '<p>Hello,</p><p>Please review the document when you have a moment.</p><p>Example sender</p></body></html>'
                    New-UDElement -Tag 'iframe' -Attributes @{
                        title = 'External email banner and example message'
                        srcDoc = $document
                        sandbox = ''
                        style = @{ width = '100%'; height = '390px'; boxSizing = 'border-box'; border = '1px solid #64748b'; borderRadius = '8px' }
                    }
                    New-UDTypography -Text 'Browser approximation. Outlook and other email clients may render the banner differently.' -GutterBottom
                    New-UDElement -Tag 'h3' -Content { 'Command for review' }
                    New-UDElement -Tag 'pre' -Attributes @{
                        style = @{ whiteSpace = 'pre-wrap'; overflowWrap = 'anywhere'; padding = '16px'; backgroundColor = '#152c42'; color = '#ffffff'; borderRadius = '8px' }
                    } -Content { $preview.Command }
                    New-UDTypography -Text 'Run manually from the repository root in an approved Exchange session. The source script may install a module and connect to Exchange even with -WhatIf. This app never runs the command.'
                }
            }
        }
    }
}
