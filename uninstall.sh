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
printf "Are you sure you want to uninstall nx53? [y/N] "
read -r REPLY
if [ "$REPLY" != "y" ] && [ "$REPLY" != "Y" ]; then
    echo
    error "Uninstallation aborted."
    exit 1
fi
echo

# 1. Stop Service
if systemctl is-active --quiet nx53; then
    info "Stopping nx53 service..."
    sudo systemctl stop nx53
fi

if systemctl is-enabled --quiet nx53; then
    info "Disabling nx53 service..."
    sudo systemctl disable nx53
fi



# 2. Remove Files
info "Removing installed files (binary, service, man pages, completions)..."
sudo rm -f /usr/local/bin/nx53
sudo rm -f /etc/systemd/system/nx53.service
sudo systemctl daemon-reload
sudo rm -f /usr/share/man/man1/nx53.1.gz

# Completions
sudo rm -f /usr/share/bash-completion/completions/nx53
sudo rm -f /etc/bash_completion.d/nx53
sudo rm -f /usr/share/zsh/vendor-completions/_nx53
sudo rm -f /usr/local/share/zsh/site-functions/_nx53
sudo rm -f /usr/share/fish/vendor_completions.d/nx53.fish

# 3. Config
printf "Do you want to remove configuration files in /etc/nx53? [y/N] "
read -r REPLY
echo
if [ "$REPLY" = "y" ] || [ "$REPLY" = "Y" ]; then
    info "Removing config directory..."
    sudo rm -rf /etc/nx53
    success "Configuration removed."
else
    warn "Configuration preserved in /etc/nx53."
fi

echo
printf "${GREEN}==>${NC} ${BOLD}Uninstallation complete!${NC}\n"
