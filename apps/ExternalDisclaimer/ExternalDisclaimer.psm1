#Requires -Version 7.0

function Get-ExternalDisclaimerPreview {
    <#
    .SYNOPSIS
        Read the existing script and prepare a preview without executing it.
    .DESCRIPTION
        Parses literal defaults and banner HTML from the repository script. Validates
        form values and produces a quoted command for manual review; never runs it.
    .PARAMETER OrgPrefix
        Organization prefix, with the same validation as the transport rule script.
    .PARAMETER Priority
        Whole number from 0 through 100. Omit to use the script default.
    .PARAMETER RuleName
        Transport rule name. Omit to use the script default.
    .PARAMETER RuleState
        Proposed state. The generated command always includes WhatIf.
    .EXAMPLE
        Get-ExternalDisclaimerPreview -OrgPrefix 'Contoso Corp'
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    .NOTES
        No Exchange connection, module installation, or job dispatch is performed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(2, 50)]
        [ValidatePattern('^[A-Za-z0-9\s]+$')]
        [string]$OrgPrefix,

        [string]$Priority,

        [string]$RuleName,

        [ValidateSet('Disabled', 'Enabled')]
        [string]$RuleState = 'Disabled'
    )

    $headerPrefix = $OrgPrefix -replace '\s+', ''
    if ($headerPrefix.Length -lt 2 -or $headerPrefix.Length -gt 50) {
        throw 'Organization prefix must contain 2-50 letters or numbers after removing whitespace.'
    }

    $sourcePath = Join-Path $PSScriptRoot '../../ExchangeOnline/New-EXOExternalDisclaimerTransportRule.ps1'
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $sourcePath, [ref]$tokens, [ref]$parseErrors
    )
    if ($parseErrors.Count) {
        throw 'The source transport rule script could not be parsed. Check it before previewing.'
    }

    $findBanner = {
        param($node)
        $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
        $node.Left.VariablePath.UserPath -eq 'BannerHtml'
    }
    $bannerAssignments = @($ast.FindAll($findBanner, $false))
    if ($bannerAssignments.Count -ne 1) {
        throw 'Expected one literal BannerHtml assignment in the source script.'
    }
    # SafeGetValue reads constants; it cannot run arbitrary source code.
    $bannerExpression = $bannerAssignments[0].Right
    if ($bannerExpression -isnot [System.Management.Automation.Language.CommandExpressionAst] -or
        $bannerExpression.Expression -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) {
        throw 'The source banner must be a literal string, without executable expressions.'
    }
    $bannerHtml = $bannerExpression.Expression.SafeGetValue()
    if ($bannerHtml -isnot [string] -or [string]::IsNullOrWhiteSpace($bannerHtml)) {
        throw 'The source banner must be a nonempty literal string.'
    }

    if (-not $PSBoundParameters.ContainsKey('RuleName')) {
        $parameter = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'RuleName' }
        $RuleName = $parameter.DefaultValue.SafeGetValue()
    }
    if ([string]::IsNullOrWhiteSpace($RuleName) -or $RuleName -match '[\r\n\x00-\x1f\x7f]') {
        throw 'Rule name is required and must be a single line without control characters.'
    }
    if (-not $PSBoundParameters.ContainsKey('Priority')) {
        $parameter = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Priority' }
        $Priority = $parameter.DefaultValue.SafeGetValue()
    }
    $priorityNumber = 0
    if ($Priority -notmatch '^[0-9]+$' -or
        -not [int]::TryParse($Priority, [ref]$priorityNumber) -or
        $priorityNumber -lt 0 -or $priorityNumber -gt 100) {
        throw 'Priority must be a whole number between 0 and 100.'
    }

    $quotedOrg = [System.Management.Automation.Language.CodeGeneration]::EscapeSingleQuotedStringContent($OrgPrefix)
    $quotedRule = [System.Management.Automation.Language.CodeGeneration]::EscapeSingleQuotedStringContent($RuleName)
    $command = "& './ExchangeOnline/New-EXOExternalDisclaimerTransportRule.ps1' -OrgPrefix '$quotedOrg' -Priority $priorityNumber -RuleName '$quotedRule'"
    if ($RuleState -eq 'Disabled') {
        $command += ' -Disabled'
    }
    $command += ' -WhatIf'

    [pscustomobject]@{
        OrgPrefix  = $OrgPrefix
        Priority   = $priorityNumber
        RuleName   = $RuleName
        RuleState  = $RuleState
        HeaderName = "X-$headerPrefix-Disclaimer-External"
        BannerHtml = $bannerHtml
        Command    = $command
    }
}

Export-ModuleMember -Function Get-ExternalDisclaimerPreview
