# External email banner proof of concept

A PowerShell Universal app for `ExchangeOnline/New-EXOExternalDisclaimerTransportRule.ps1`.
It provides organization prefix, rule name, priority, and proposed state controls;
an email banner preview; and a safely quoted command containing `-WhatIf`.
The initial `Contoso Corp` value is sample data.

The app **does not execute the transport rule script**, install modules, connect to
Exchange, or submit automation jobs. Selecting Enabled only changes the proposed
state shown in the preview. The source script is unchanged.

## Load from this repository

The `.universal/dashboards.ps1` registration points to this app and requires authentication.
When this checkout is the PSU repository, load its configuration and open
`/external-email-banner`. Keep `ExternalDisclaimer.ps1` and
`ExternalDisclaimer.psm1` together in `apps/ExternalDisclaimer`.
Do not create a second app at the same URL if the registration already loaded.

Select an existing **PowerShell 7** environment for this app in PSU's Execution
settings. No credential or ExchangeOnlineManagement module is needed for the preview.
The registration leaves the environment unspecified because environment names
are specific to your server; ensure its default is PowerShell 7 or select one.

## Using the Create App dialog instead

| Setting | Value |
| --- | --- |
| Name | External Email Banner POC |
| URL | `/external-email-banner` |
| Description | Preview external email disclaimer transport rules |
| Definition | Code |
| Environment | Your existing PowerShell 7 environment |
| Credential | Leave blank |
| Authentication | Checked |
| Roles | Select an existing role if you want to restrict the preview further |

After saving, the editor's **Code** tab takes `ExternalDisclaimer.ps1`; the
**Module** tab takes `ExternalDisclaimer.psm1`. The app imports the matching module
beside its code, and PSU makes that module's helper available to event handlers.
The directory layout above is required: the helper reads the source script at
`../../ExchangeOnline/New-EXOExternalDisclaimerTransportRule.ps1` relative to itself.
Prefer the repository registration so these paths stay intact. If the dialog
creates code in a different directory, use the repository file as its definition
instead of pasting into that location.

## Behavior and limits

- Source defaults and banner HTML are read through PowerShell's AST and
  `SafeGetValue`; the source script is never dot-sourced or invoked.
- Preview values are stored per browser session, not in shared app cache.
- Prefix and priority validation match the source's intended limits. Rule names
  must additionally be nonblank, single-line strings without control characters.
- The source banner is displayed in an iframe with an empty sandbox and a
  restrictive content security policy. User-entered values are displayed as text.
- Generated commands quote ASCII and typographic apostrophes, and always include
  `-WhatIf`. They are only text. Running the original script manually may install
  ExchangeOnlineManagement and connect to Exchange **before** its WhatIf check.
- Email client rendering and live rule state are not simulated or verified.
- Targets your PowerShell Universal **2026.3.4** server using the documented
  PSU 5 / 2026 app APIs. Startup and browser behavior must still be checked on
  that server; no PSU runtime is installed in the local development environment.

## References

- [Apps and companion modules](https://github.com/ironmansoftware/universal-docs/blob/v5/apps/building-dashboards.md)
- [Forms and validation](https://github.com/ironmansoftware/universal-docs/blob/v5/apps/components/inputs/form.md)
- [Repository configuration and dashboards.ps1](https://github.com/ironmansoftware/universal-docs/blob/v5/config/repository.md#dashboardsps1)
- [New-PSUApp registration](https://github.com/ironmansoftware/universal-docs/blob/v5/cmdlets/New-PSUApp.txt)
