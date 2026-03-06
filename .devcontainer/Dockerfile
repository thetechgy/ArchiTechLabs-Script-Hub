# syntax=docker/dockerfile:1
FROM cgr.dev/chainguard/wolfi-base:latest

ARG PS_VERSION=7.5.4
ARG PESTER_VERSION=5.7.1
ARG PSSA_VERSION=1.24.0
ARG TARGETARCH
ARG ENABLE_AI_TOOLS=true
ARG BUILDKIT_INLINE_CACHE=1
ARG IMAGE_TITLE="PowerShell Dev Container"
ARG IMAGE_DESCRIPTION="Wolfi-based PowerShell development container"
ARG IMAGE_SOURCE="https://github.com/thetechgy/ArchiTechLabs-Script-Hub"
ARG IMAGE_LICENSES="MIT"
ARG VCS_REF="unknown"
ARG BUILD_DATE="unknown"

LABEL org.opencontainers.image.title="${IMAGE_TITLE}" \
      org.opencontainers.image.description="${IMAGE_DESCRIPTION}" \
      org.opencontainers.image.source="${IMAGE_SOURCE}" \
      org.opencontainers.image.licenses="${IMAGE_LICENSES}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}"

# -----------------------------
# Base OS packages (always needed)
# -----------------------------
RUN apk add --no-cache \
    bash \
    ca-certificates \
    curl \
    git \
    gnupg-gpgconf \
    openssh-client \
    icu-libs \
    libstdc++ \
    libgcc

# -----------------------------
# Install PowerShell
# -----------------------------
RUN : "${TARGETARCH:?TARGETARCH must be set by BuildKit}" \
    && case "${TARGETARCH}" in \
    amd64) PS_ARCH="x64" ;; \
    arm64) PS_ARCH="arm64" ;; \
    *) echo "Unsupported TARGETARCH=${TARGETARCH}" && exit 1 ;; \
    esac \
    && PS_TARBALL="powershell-${PS_VERSION}-linux-${PS_ARCH}.tar.gz" \
    && mkdir -p "/opt/microsoft/powershell/${PS_VERSION}" \
    && curl -fsSL -o "/tmp/${PS_TARBALL}" \
    "https://github.com/PowerShell/PowerShell/releases/download/v${PS_VERSION}/${PS_TARBALL}" \
    && curl -fsSL -o /tmp/hashes.sha256 \
    "https://github.com/PowerShell/PowerShell/releases/download/v${PS_VERSION}/hashes.sha256" \
    && PS_EXPECTED_SHA256="" \
    && while IFS= read -r checksum_line; do \
        case "${checksum_line}" in \
            *"${PS_TARBALL}"*) PS_EXPECTED_SHA256="${checksum_line%% *}"; break ;; \
        esac; \
    done < /tmp/hashes.sha256 \
    && [ -n "${PS_EXPECTED_SHA256}" ] \
    && PS_EXPECTED_SHA256="$(printf '%s' "${PS_EXPECTED_SHA256}" | tr '[:upper:]' '[:lower:]')" \
    && set -- $(sha256sum "/tmp/${PS_TARBALL}") \
    && PS_ACTUAL_SHA256="$1" \
    && if [ "${PS_ACTUAL_SHA256}" != "${PS_EXPECTED_SHA256}" ]; then \
        echo "Checksum mismatch for ${PS_TARBALL}" >&2; \
        echo "Expected: ${PS_EXPECTED_SHA256}" >&2; \
        echo "Actual:   ${PS_ACTUAL_SHA256}" >&2; \
        exit 1; \
    fi \
    && tar -xzf "/tmp/${PS_TARBALL}" -C "/opt/microsoft/powershell/${PS_VERSION}" \
    && rm -f "/tmp/${PS_TARBALL}" /tmp/hashes.sha256 \
    && chmod 755 "/opt/microsoft/powershell/${PS_VERSION}/pwsh" \
    && chmod -R a+rX "/opt/microsoft/powershell/${PS_VERSION}" \
    && mkdir -p /usr/local/bin \
    && ln -sf "/opt/microsoft/powershell/${PS_VERSION}/pwsh" /usr/local/bin/pwsh \
    && ln -sf "/opt/microsoft/powershell/${PS_VERSION}/pwsh" /usr/bin/pwsh \
    && pwsh -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'

# -----------------------------
# PowerShell tooling (always needed)
# -----------------------------
RUN pwsh -NoLogo -NoProfile -Command "\
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted; \
    Install-Module Pester -RequiredVersion ${PESTER_VERSION} -Scope AllUsers -Force -AllowClobber; \
    Install-Module PSScriptAnalyzer -RequiredVersion ${PSSA_VERSION} -Scope AllUsers -Force -AllowClobber; \
    Import-Module Pester -RequiredVersion ${PESTER_VERSION} -Force; \
    Import-Module PSScriptAnalyzer -RequiredVersion ${PSSA_VERSION} -Force; \
    "

# -----------------------------
# Non-root user for devcontainers
# -----------------------------
RUN adduser -D -u 1000 vscode \
    && mkdir -p /home/vscode \
    && chown -R vscode:vscode /home/vscode

# Avoid git dubious-ownership warnings for the fixed devcontainer workspace path.
RUN git config --system --add safe.directory /workspace

# -----------------------------
# AI tooling + CLIs (optional)
# -----------------------------
RUN if [ "${ENABLE_AI_TOOLS}" = "true" ]; then \
    echo 'Installing AI assist tooling + Node + Codex + Claude...' && \
    apk add --no-cache \
    nodejs-22 \
    npm \
    bubblewrap \
    socat \
    procps \
    gh \
    delta \
    fzf \
    ripgrep \
    fd \
    jq \
    yq \
    patch \
    diffutils \
    sed \
    gawk \
    coreutils \
    findutils \
    tree \
    gzip \
    unzip \
    xz \
    && mkdir -p /etc/profile.d \
    && printf '%s\n' \
    'export PATH="$HOME/.local/bin:$PATH"' \
    > /etc/profile.d/00-devcontainer-paths.sh \
    && su -s /bin/bash vscode -c ' \
    set -euo pipefail; \
    export PATH="$HOME/.local/bin:$PATH"; \
    mkdir -p "$HOME/.local" "$HOME/.npm"; \
    npm config set prefix "$HOME/.local"; \
    npm config set cache "$HOME/.npm"; \
    node --version; npm --version; \
    npm i -g @openai/codex@latest; \
    codex --version || true; \
    mkdir -p "$HOME/.local/bin"; \
    curl -fsSL https://claude.ai/install.sh | bash; \
    command -v claude >/dev/null 2>&1 && claude --version || true; \
    ' \
    ; else \
    echo 'AI tooling disabled (ENABLE_AI_TOOLS=false)'; \
    fi

USER vscode
WORKDIR /workspaces
