@{
    # Keep signal high for a shared repo. Info-level findings tend to create noise.
    Severity     = @('Error', 'Warning')

    # Rules excluded intentionally due to common false-positives or known analyzer issues.
    ExcludeRules = @(
        # Frequently noisy with splatting, scriptblocks, and dynamic parameter patterns.
        'PSReviewUnusedParameter'

        # Known to be unstable/buggy in some analyzer versions/patterns.
        'AvoidReservedCharInCmdlet'
    )

    Rules        = @{

        # ---------------------------------------------------------------------
        # Compatibility (PS 5.1 + PS 7)
        # ---------------------------------------------------------------------
        PSUseCompatibleSyntax                          = @{
            Enable         = $true
            # Enforces syntax that works in BOTH Windows PowerShell 5.1 and PowerShell 7+.
            TargetVersions = @('5.1', '7.0')
        }

        # ---------------------------------------------------------------------
        # Authoring / maintainability
        # ---------------------------------------------------------------------
        PSUseApprovedVerbs                             = @{
            Enable = $true
        }

        PSProvideCommentHelp                           = @{
            Enable       = $true
            # Public surface should be documented; internal helpers are often too noisy to enforce globally.
            ExportedOnly = $true
        }

        PSUseShouldProcessForStateChangingFunctions    = @{
            Enable = $true
        }

        PSAvoidGlobalVars                              = @{
            Enable = $true
        }

        # ---------------------------------------------------------------------
        # Security / unsafe patterns
        # ---------------------------------------------------------------------
        PSAvoidUsingInvokeExpression                   = @{
            Enable = $true
        }

        PSAvoidUsingConvertToSecureStringWithPlainText = @{
            Enable = $true
        }

        PSAvoidUsingPlainTextForPassword               = @{
            Enable = $true
        }

        # ---------------------------------------------------------------------
        # Team-consistent readability (minimal, to reduce diff churn)
        # ---------------------------------------------------------------------
        PSAvoidUsingCmdletAliases                      = @{
            Enable = $true
        }

        PSAvoidUsingWriteHost                          = @{
            Enable = $true
        }

        PSUseConsistentIndentation                     = @{
            Enable          = $true
            IndentationSize = 4
            Kind            = 'space'
        }

        PSPlaceOpenBrace                               = @{
            Enable             = $true
            OnSameLine         = $true
            IgnoreOneLineBlock = $true
        }

        PSPlaceCloseBrace                              = @{
            Enable             = $true
            NoEmptyLineBefore  = $true
            IgnoreOneLineBlock = $true
        }

        # Intentionally NOT forcing these (higher churn / opinionated style policing):
        PSUseConsistentWhitespace                      = @{ Enable = $false }
        PSAlignAssignmentStatement                     = @{ Enable = $false }
    }
}
