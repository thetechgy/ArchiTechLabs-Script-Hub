# Codex Policy Notes (Strict Workspace Safety)

This repository uses a strict Codex approval policy for cross-platform use on:

- Windows 11 (`powershell` / `pwsh`)
- Devcontainer environments

## Intent

- Keep `approval_policy = "untrusted"` and `sandbox_mode = "workspace-write"`.
- Keep network access disabled in workspace sandbox (`network_access = false`).
- Use a narrow allowlist in `.codex/rules/default.rules` for expected low-risk workflows.

## Important Limitation

`allow` rules are convenience controls for command prefixes. They are **not** a workspace-path guard and do not prove a command is read-only.

Because of that, this repo does **not** allow broad command prefixes such as:

- generic shell wrappers (for example `pwsh -Command ...`, `bash -lc ...`)
- broad read command families (`ls`, `cat`, `find`, etc.)

Extra read commands may still require approval by design.

## Expected No-Prompt Commands

- Selected git read operations (`status`, `diff`, `log`, `show`, `rev-parse`, `branch --show-current`, `ls-files`)
- Repo check script (`Invoke-RepoChecks.ps1`) in `pwsh` and `powershell`
- Direct analyzer/test commandlets:
  - `Invoke-ScriptAnalyzer`
  - `Invoke-Pester`

All other commands are intentionally reviewed case-by-case.
