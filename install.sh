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
    echo "    nx53 - DoS Mitigation Installer     "
    echo "========================================"
    printf "${NC}\n"
}

print_header

# Helper function to check command existence
check_cmd() {
    command -v "$1" > /dev/null 2>&1
}

# --- 1. Dependency Check & Installation ---

info "[1/5] Checking System Dependencies..."

if check_cmd apt-get; then
    # Debian/Ubuntu
    printf "%b\n" "${BOLD}Detected Debian/Ubuntu system.${NC}"
    printf "%b\n" "Updating package index..."
    sudo apt-get update
    printf "%b\n" "The following packages will be installed: ${BOLD}build-essential libpcap-dev pkg-config libssl-dev curl git nftables libnftnl-dev${NC}"
    printf "%b\n" "You will be prompted to confirm installation and see the size."
    sudo apt-get install build-essential libpcap-dev pkg-config libssl-dev curl git nftables libnftnl-dev
elif check_cmd dnf; then
    # Fedora/RHEL
    printf "%b\n" "${BOLD}Detected Fedora system.${NC}"
    printf "%b\n" "The following packages will be installed: ${BOLD}@development-tools libpcap-devel openssl-devel curl git nftables libnftnl-devel${NC}"
    sudo dnf install @development-tools libpcap-devel openssl-devel curl git nftables libnftnl-devel
elif check_cmd pacman; then
    # Arch Linux
    printf "%b\n" "${BOLD}Detected Arch Linux.${NC}"
    printf "%b\n" "The following packages will be installed: ${BOLD}base-devel libpcap openssl curl git nftables libnftnl${NC}"
    sudo pacman -S base-devel libpcap openssl curl git nftables libnftnl
elif check_cmd brew; then
    # MacOS
    printf "%b\n" "${BOLD}Detected macOS (Homebrew).${NC}"
    printf "%b\n" "The following packages will be installed: ${BOLD}libpcap openssl git${NC}"
    brew install libpcap openssl git
else
    warn "Warning: Could not detect package manager. Please ensure 'build-essential', 'libpcap', and 'git' are installed."
fi

# Check for Rust
echo
if ! check_cmd cargo; then
    info "Rust not found. Installing via rustup..."
    # read -p "Install Rust? [y/N] " -n 1 -r
    # We'll just let rustup handle its own prompt or default to yes if we want, but user asked for confirmation.
    # Actually rustup has an interactive mode by default without -y.
    
    printf "Rustup installer will run now. It will display download size and ask for confirmation.\n"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    . "$HOME/.cargo/env"

else
    success "Rust is already installed."
fi

# --- 2. Clone & Build ---
# Check if we are in the repo, if not clone it
CLONED_DIR=""
# We check for Cargo.toml AND if it contains nx53 to be sure we're in the right place
if [ ! -f "Cargo.toml" ] || ! grep -q "nx53" Cargo.toml; then

    info "Not inside nx53 repository. Cloning to temporary directory..."
    CLONED_DIR=$(mktemp -d)
    echo "Cloning into $CLONED_DIR..."
    git clone https://github.com/hapara-fail/nx53.git "$CLONED_DIR"
    cd "$CLONED_DIR"
fi

info "[2/5] Building nx53..."
cargo build --release

# --- 3. Profile Selection ---
info "[3/5] Configuration Wizard"
echo "Select a traffic profile for your deployment:"
printf "1) ${GREEN}Home/Small Office${NC} (10k requests/day)\n"
printf "2) ${GREEN}School/Medium Office${NC} (50k requests/day) [Default]\n"
printf "3) ${GREEN}Enterprise${NC} (100k requests/day)\n"
printf "4) ${GREEN}ISP/Datacenter${NC} (1M requests/day)\n"

while true; do
    # Try to read from tty if available
    if [ -t 0 ]; then
        printf "Enter choice [1-4]: "
        read -r choice
    elif [ -c /dev/tty ]; then
        # if piped, try reading from /dev/tty
        printf "Enter choice [1-4]: " > /dev/tty
        read -r choice < /dev/tty
    else
        echo "Non-interactive mode detected. Defaulting to 'School'."
        choice="2"
        break
    fi

    # Check input
    if [ -z "$choice" ]; then
        choice="2"
        break
    elif [ "$choice" = "1" ] || [ "$choice" = "2" ] || [ "$choice" = "3" ] || [ "$choice" = "4" ]; then
        break
    else
        echo "Invalid choice. Please enter a number between 1 and 4."
    fi
done

PROFILE_NAME="School"

case $choice in
  1) PROFILE_NAME="Home" ;;
  2) PROFILE_NAME="School" ;;
  3) PROFILE_NAME="Enterprise" ;;
  4) PROFILE_NAME="Datacenter" ;;
  *) echo "Invalid choice or default used. Setting to School." ;;
esac

# --- 4. Install & Configure ---
info "[4/5] Installing Service..."

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/nx53"

# Install Binary
echo "Installing binary to $INSTALL_DIR..."
sudo cp target/release/nx53 "$INSTALL_DIR/"
sudo chmod +x "$INSTALL_DIR/nx53"

# Install Man Page
echo "Installing man page..."
# Find man page, allowing for build artifacts
MAN_FILE=$(find target/release/build -name "nx53.1" | head -n 1)

if [ -n "$MAN_FILE" ]; then
    sudo mkdir -p /usr/share/man/man1
    sudo cp "$MAN_FILE" /usr/share/man/man1/
    sudo gzip -f /usr/share/man/man1/nx53.1
    echo "Man page installed to /usr/share/man/man1/nx53.1.gz"
else
    warn "Warning: Could not find generated man page."
fi

# Install Completions
echo "Installing shell completions..."
# Ensure COMP_DIR is found relative to MAN_FILE if it exists, otherwise check target structure
if [ -n "$MAN_FILE" ]; then
    COMP_DIR=$(dirname "$MAN_FILE")/../completions
    
    # Bash
    if [ -d "/usr/share/bash-completion/completions" ]; then
        sudo cp "$COMP_DIR/nx53.bash" /usr/share/bash-completion/completions/nx53
    elif [ -d "/etc/bash_completion.d" ]; then
        sudo cp "$COMP_DIR/nx53.bash" /etc/bash_completion.d/nx53
    fi

    # Zsh
    if [ -d "/usr/share/zsh/vendor-completions" ]; then
        sudo cp "$COMP_DIR/_nx53" /usr/share/zsh/vendor-completions/
    elif [ -d "/usr/local/share/zsh/site-functions" ]; then
        sudo cp "$COMP_DIR/_nx53" /usr/local/share/zsh/site-functions/
    fi

    # Fish
    if [ -d "/usr/share/fish/vendor_completions.d" ]; then
        sudo cp "$COMP_DIR/nx53.fish" /usr/share/fish/vendor_completions.d/
    fi
fi

# Create Config Directory
echo "Creating config directory at $CONFIG_DIR..."
sudo mkdir -p "$CONFIG_DIR"

# Generate Config
echo "Generating config.toml..."
cat <<EOF | sudo tee "$CONFIG_DIR/config.toml" > /dev/null
# nx53 Configuration
# Auto-generated by install.sh

mode = "normal"
profile = "$PROFILE_NAME"

# Uncomment to override profile defaults:
# threshold_override = 75000
EOF

# --- 5. Systemd Service ---
info "[5/5] Configuring Systemd Service..."

if check_cmd systemctl; then
    cat <<EOF | sudo tee /etc/systemd/system/nx53.service > /dev/null
[Unit]
Description=nx53 DNS Firewall
After=network.target

[Service]
ExecStart=$INSTALL_DIR/nx53
WorkingDirectory=$CONFIG_DIR
Restart=always
User=root
# Adjust capabilities if running as non-root (cap_net_raw, cap_net_admin) covers pcap/iptables
# User=nx53
# AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF

    echo "Reloading systemd daemon..."
    sudo systemctl daemon-reload
    echo "Enabling nx53 service..."
    sudo systemctl enable nx53
    echo "Starting nx53 service..."
    sudo systemctl start nx53
    
    success "Service installed and started!"
    echo "Check status with: ${BOLD}sudo systemctl status nx53${NC}"
else
    warn "Systemd not found. Skipping service installation."
    echo "You can run nx53 manually: ${BOLD}sudo $INSTALL_DIR/nx53${NC}"
fi

# Cleanup if cloned
if [ -n "$CLONED_DIR" ]; then
    echo "Cleaning up temporary files..."
    rm -rf "$CLONED_DIR"
fi

success "Installation complete!"
