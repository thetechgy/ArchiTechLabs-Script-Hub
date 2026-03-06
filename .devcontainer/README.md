# Development Container (`.devcontainer/`)

## Overview

This directory defines a reusable VS Code devcontainer for PowerShell development on a Wolfi base image.

Primary goals:

- Consistent PowerShell tooling across machines
- Fast onboarding with minimal host setup
- Reasonable hardening for development workloads without breaking day-to-day workflows

## Current Defaults

- Base image: `cgr.dev/chainguard/wolfi-base:latest`
- PowerShell version arg: `PS_VERSION=7.5.4`
- Core modules pinned to CI parity:
  - `Pester=5.7.1`
  - `PSScriptAnalyzer=1.24.0`
- AI tooling: enabled by default (`ENABLE_AI_TOOLS=true`)
- Runtime user: `vscode` (non-root)
- Container init enabled (`init: true`)
- Explicit workspace mount/folder: host repo is mounted at `/workspace`
- Musl compatibility env for Claude tooling: `USE_BUILTIN_RIPGREP=0`

## Security and Reliability Controls

The current config includes the following controls:

- Non-root development user (`remoteUser: vscode`)
- UID/GID alignment enabled (`updateRemoteUserUID: true`)
- Runtime hardening via `runArgs`:
  - `--security-opt=no-new-privileges`
  - `--cap-drop=ALL`
  - `--cap-add=DAC_OVERRIDE`
- Read-only bind mount of `.devcontainer` into the container at `/workspace/.devcontainer`
  - This reduces risk of in-container tampering with `devcontainer.json` / `Dockerfile` before a rebuild.
- Minimal init process enabled (`init: true`) to improve PID 1 signal handling and child process reaping
- Telemetry opt-out environment variables for .NET and PowerShell
- PowerShell tarball SHA-256 verification before extraction
- Strict shell behavior (`set -euo pipefail`) in the optional AI tooling setup block
- Build context locked down via `.dockerignore`
- OCI image labels for title/description/source/license/revision/created metadata
- Optional Claude sandbox prerequisites included when AI tooling is enabled (`bubblewrap`, `socat`)
- Git `safe.directory` pre-registration for `/workspace` to reduce Podman ownership-warning churn during attach
- Capability model rationale:
  - `--cap-drop=ALL` remains the baseline.
  - `DAC_OVERRIDE` is explicitly re-added because VS Code server install/setup in this Podman flow may execute through a root session that must create paths under `/vscode/vscode-server`.
  - This avoids startup permission failures without host-side permission mutation scripts.

Guardrails:

- Do not add Linux capabilities beyond `DAC_OVERRIDE` unless explicitly required.
- Do not add `SYS_ADMIN` for this devcontainer profile.

## Post-Create Validation

`postCreateCommand` imports required versions and fails if version requirements are not met. It then prints versions for:

- `pwsh`
- `Pester`
- `PSScriptAnalyzer`

## Workspace and Persistence Model

- Workspace path inside container is `/workspace` (set explicitly in `devcontainer.json`).
- `.devcontainer` is mounted read-only inside the container to help protect host-side devcontainer config from in-container modification.
- No repo-managed persistent dev volumes are configured in `devcontainer.json`.
- VS Code Dev Containers may mount a shared external `vscode` volume at `/vscode` for VS Code server and extension cache data.
- Rebuilds still reset most runtime state (for example, shell history/tool config) unless you add additional mounts.

## Files in This Directory

- `devcontainer.json`: Devcontainer runtime settings, hardening `runArgs`, env vars, post-create validation
- `Dockerfile`: Image build logic and tooling installation
- `.dockerignore`: Restricts build context to devcontainer files
- `README.md`: This document

## Build Arguments

Supported Docker build args:

- `PS_VERSION` (default: `7.5.4`)
- `PESTER_VERSION` (default: `5.7.1`)
- `PSSA_VERSION` (default: `1.24.0`)
- `ENABLE_AI_TOOLS` (default: `true`)
- `TARGETARCH` (must be provided by BuildKit/devcontainer tooling)
- `BUILDKIT_INLINE_CACHE` (default: `1`, consumed to avoid noisy build warnings)
- `IMAGE_TITLE`
- `IMAGE_DESCRIPTION`
- `IMAGE_SOURCE`
- `IMAGE_LICENSES`
- `VCS_REF`
- `BUILD_DATE`

Notes:

- `TARGETARCH` has no fallback default by design. Builds fail fast if it is missing.
- The current image policy intentionally tracks latest Wolfi base and latest OS package versions at build time.
- PowerShell module versions are pinned to the same versions used in CI for local/CI parity.

## Podman + VS Code Setup

This repo is tested with Podman on Linux and Windows+WSL.

Minimum VS Code setting:

```json
{
  "dev.containers.dockerPath": "podman"
}
```

Optional if you use compose-based devcontainers:

```json
{
  "dev.containers.dockerComposePath": "podman-compose"
}
```

Roadmap: Evaluate VS Code volume-based workspace workflow (Clone in Volume) as a future improvement for performance and reduced host-to-container exposure.

## AI Tooling (Default On)

AI tooling is enabled by default (`ENABLE_AI_TOOLS=true`). For constrained environments, you can opt out by setting `ENABLE_AI_TOOLS=false` in a local devcontainer override.

When enabled, the image installs:

- Wolfi Node runtime (`nodejs-22`, `npm`) and package-management install flow
- Codex CLI via npm (`@openai/codex@latest`) with user-local npm prefix under `/home/vscode/.local`
- Claude Code via native installer (`curl -fsSL https://claude.ai/install.sh | bash`)
- Claude sandbox prerequisites on Linux/WSL (`bubblewrap`, `socat`)
- additional workflow tools (`delta`, `fzf`, `gh`)
- common CLI helpers (`ripgrep`, `fd`, `jq`, `yq`, `patch`, `diffutils`, `tree`, etc.)

Wolfi/musl notes:

- `USE_BUILTIN_RIPGREP=0` is set in `containerEnv` for Claude compatibility on musl-based distributions.
- Required runtime libraries are present in the base image (`libgcc`, `libstdc++`) and `ripgrep` is installed in the AI tooling path.

Sandboxing notes:

- This profile is optimized for strong outer container isolation plus Claude nested sandbox support.
- Codex nested Docker firewall sandboxing (`NET_ADMIN`/`NET_RAW` + allowlists) is intentionally not enabled in this default hardened profile.

This path can be disabled for constrained environments and is not required for PowerShell module development.

## Expected Log Noise (Can Be Ignored)

You may still see these warnings from VS Code/Podman internals during container startup:

- `Ignoring option 'skip-requirements-check' ...`
- `Error: AttachConsole failed` (transient Windows ConPTY/node-pty noise; non-fatal when container startup and attach succeed)
- `safe.directory: Failed to get host owner ... powershell.exe ENOENT` (host owner probe noise on some Windows/WSL Podman paths; non-fatal when attach succeeds)

These come from generated helper images or VS Code server internals, not from functional issues in this repo's devcontainer configuration.

## Usage

1. Open the repository in VS Code.
2. Run `Dev Containers: Reopen in Container`.
3. Wait for the first build to complete.
4. Confirm post-create output includes `pwsh`, `Pester`, and `PSScriptAnalyzer` version lines.

## Non-Goals

This devcontainer is for development convenience and consistency. It is not intended as:

- A production runtime image
- A hardened service container profile
- A published, immutable release image
