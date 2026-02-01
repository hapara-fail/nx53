#!/bin/bash
set -e

# Colors and Formatting
BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'



# Formatting helpers
info() {
    printf "${BLUE}==>${NC} ${BOLD}%s${NC}\n" "$1"
    echo
}

success() {
    printf "${GREEN}==>${NC} ${BOLD}%s${NC}\n" "$1"
    echo
}

warn() {
    printf "${YELLOW}==>${NC} ${BOLD}%s${NC}\n" "$1"
    echo
}

error() {
    printf "${RED}==>${NC} ${BOLD}%s${NC}\n" "$1"
    echo
}

remove_path() {
    local target="$1"
    
    # Treat existing files, directories, and symlinks as removable targets.
    if [ -e "$target" ] || [ -L "$target" ]; then
        info "Removing $target..."
        if [ -d "$target" ]; then
            sudo rm -rf "$target"
        else
            sudo rm -f "$target"
        fi
    else
        warn "Not found (already removed?): $target"
    fi
}

print_header() {
    clear
    printf "${CYAN}"
    echo "========================================"
    echo "           nx53 - Uninstaller           "
    echo "========================================"
    printf "${NC}\n"
}

print_header

# Confirmation
echo "This will uninstall nx53 and perform the following actions:"
echo "  • Stop and disable the nx53 service"
echo "  • Remove the nx53 binary from /usr/local/bin"
echo "  • Remove the man page and shell completions"
echo "  • Optionally remove configuration files in /etc/nx53"
echo
printf "Are you sure you want to continue? [y/N] "
read -r REPLY < /dev/tty
if [ "$REPLY" != "y" ] && [ "$REPLY" != "Y" ]; then
    echo
    error "Uninstallation aborted."
    exit 1
fi
echo

# 1. Stop Service
set +e
systemctl is-active --quiet nx53
ACTIVE_STATUS=$?
set -e
if [ "$ACTIVE_STATUS" -eq 0 ]; then
    info "Stopping nx53 service..."
    set +e
    sudo systemctl stop nx53
    STOP_STATUS=$?
    set -e
    if [ "$STOP_STATUS" -ne 0 ]; then
        warn "Failed to stop nx53 service (systemctl exit code: $STOP_STATUS)."
    fi
elif [ "$ACTIVE_STATUS" -ne 3 ] && [ "$ACTIVE_STATUS" -ne 4 ]; then
    # 3: inactive, 4: unknown unit – treat others as unexpected failures
    warn "Could not determine nx53 service status (systemctl exit code: $ACTIVE_STATUS)."
fi

set +e
systemctl is-enabled --quiet nx53
ENABLED_STATUS=$?
set -e
if [ "$ENABLED_STATUS" -eq 0 ]; then
    info "Disabling nx53 service..."
    set +e
    sudo systemctl disable nx53
    DISABLE_STATUS=$?
    set -e
    if [ "$DISABLE_STATUS" -ne 0 ]; then
        warn "Failed to disable nx53 service (systemctl exit code: $DISABLE_STATUS)."
    fi
elif [ "$ENABLED_STATUS" -ne 1 ] && [ "$ENABLED_STATUS" -ne 4 ]; then
    # 1: disabled, 4: unknown unit – treat others as unexpected failures
    warn "Could not determine if nx53 service is enabled (systemctl exit code: $ENABLED_STATUS)."
fi



# 2. Remove Files
info "Removing installed files (binary, service, man pages, completions)..."
remove_path "/usr/local/bin/nx53"
remove_path "/etc/systemd/system/nx53.service"
info "Reloading systemd daemon..."
set +e
sudo systemctl daemon-reload
RELOAD_STATUS=$?
set -e
if [ "$RELOAD_STATUS" -ne 0 ]; then
    warn "Failed to reload systemd daemon (systemctl exit code: $RELOAD_STATUS). You may need to run 'sudo systemctl daemon-reload' manually."
fi
remove_path "/usr/share/man/man1/nx53.1.gz"

# Completions
remove_path "/usr/share/bash-completion/completions/nx53"
remove_path "/etc/bash_completion.d/nx53"
remove_path "/usr/share/zsh/vendor-completions/_nx53"
remove_path "/usr/local/share/zsh/site-functions/_nx53"
remove_path "/usr/share/fish/vendor_completions.d/nx53.fish"

# 3. Config
printf "Do you want to remove configuration files in /etc/nx53? [y/N] "
read -r REPLY < /dev/tty
echo
if [ "$REPLY" = "y" ] || [ "$REPLY" = "Y" ]; then
    info "Removing config directory..."
    remove_path "/etc/nx53"
    success "Configuration removed."
else
    warn "Configuration preserved in /etc/nx53."
fi

echo
printf "${GREEN}==>${NC} ${BOLD}Uninstallation complete!${NC}\n"
