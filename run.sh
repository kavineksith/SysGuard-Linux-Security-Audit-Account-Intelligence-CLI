#!/usr/bin/env bash
# =============================================================================
# run.sh — Bootstrap and launcher for sysguard
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/.venv"
MIN_PY_MAJOR=3
MIN_PY_MINOR=11

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'
CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; RESET=$'\033[0m'

info()    { printf "${CYAN}[INFO]${RESET} %s\n" "$1"; }
success() { printf "${GREEN}[OK]${RESET}   %s\n" "$1"; }
warn()    { printf "${YELLOW}[WARN]${RESET} %s\n" "$1"; }
error()   { printf "${RED}[ERR]${RESET}  %s\n" "$1" >&2; }
die()     { error "$1"; exit 1; }

# ---------------------------------------------------------------------------
# Find a suitable Python interpreter
# ---------------------------------------------------------------------------
find_python() {
    local candidates=(python3.13 python3.12 python3.11 python3)
    for c in "${candidates[@]}"; do
        if command -v "$c" &>/dev/null; then
            local ver
            ver=$("$c" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')
            local major="${ver%%.*}"
            local minor="${ver##*.}"
            if (( major > MIN_PY_MAJOR || (major == MIN_PY_MAJOR && minor >= MIN_PY_MINOR) )); then
                echo "$c"
                return 0
            fi
        fi
    done
    return 1
}

startup_banner() {
    printf "\n${CYAN}${BOLD}"
    printf "╔══════════════════════════════════════════════╗\n"
    printf "║   sysguard — Security Audit CLI Bootstrap     ║\n"
    printf "╚══════════════════════════════════════════════╝\n"
    printf "${RESET}\n"
}

startup_banner

PY_BIN="$(find_python)" || die "Python ${MIN_PY_MAJOR}.${MIN_PY_MINOR}+ not found. Install Python 3.11 or newer."
success "Python interpreter: $($PY_BIN --version)"

# ---------------------------------------------------------------------------
# Create / reuse virtual environment
# ---------------------------------------------------------------------------
if [[ ! -d "$VENV_DIR" ]]; then
    info "Creating virtual environment at $VENV_DIR ..."
    "$PY_BIN" -m venv "$VENV_DIR" || die "Failed to create virtualenv"
    success "Virtual environment created"
else
    success "Virtual environment found: $VENV_DIR"
fi

VENV_PY="${VENV_DIR}/bin/python"
VENV_PIP="${VENV_DIR}/bin/pip"

# ---------------------------------------------------------------------------
# Install / update package (idempotent — only reinstall if needed)
# ---------------------------------------------------------------------------
MARKER_FILE="${VENV_DIR}/.installed"
SETUP_HASH_FILE="${VENV_DIR}/.setup_hash"
CURRENT_HASH=$(cat "${SCRIPT_DIR}/setup.cfg" "${SCRIPT_DIR}/requirements.txt" 2>/dev/null | md5sum | cut -d' ' -f1)

if [[ ! -f "$MARKER_FILE" ]] || [[ "$(cat "$SETUP_HASH_FILE" 2>/dev/null || echo '')" != "$CURRENT_HASH" ]]; then
    info "Installing sysguard and dependencies (this may take a moment)..."
    "$VENV_PIP" install --quiet --upgrade pip
    "$VENV_PIP" install --quiet -e "$SCRIPT_DIR"
    "$VENV_PIP" install --quiet -r "${SCRIPT_DIR}/requirements.txt"
    touch "$MARKER_FILE"
    echo "$CURRENT_HASH" > "$SETUP_HASH_FILE"
    success "Installation complete"
else
    success "Dependencies up to date"
fi

# ---------------------------------------------------------------------------
# Root privilege notice
# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    warn "Not running as root — /etc/shadow and some system data will be inaccessible."
    warn "For a full security audit: sudo bash run.sh ..."
fi

printf "\n${GREEN}${BOLD}Environment ready — launching sysguard...${RESET}\n\n"

# ---------------------------------------------------------------------------
# Hand off to the actual CLI
# ---------------------------------------------------------------------------
exec "$VENV_PY" -m sysguard.cli.main "$@"
