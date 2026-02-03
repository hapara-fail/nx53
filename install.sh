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

# Parse command line arguments
BUILD_FROM_SOURCE=false
for arg in "$@"; do
    case $arg in
        --build-from-source)
            BUILD_FROM_SOURCE=true
            shift
            ;;
    esac
done

# --- Attempt Pre-built Binary Download ---
BINARY_DOWNLOADED=false

if [ "$BUILD_FROM_SOURCE" = false ]; then
    info "[1/5] Attempting to download pre-built binary..."
    
    # Detect architecture
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            DOWNLOAD_ARCH="x86_64"
            ;;
        aarch64|arm64)
            DOWNLOAD_ARCH="aarch64"
            ;;
        *)
            warn "Unsupported architecture: $ARCH. Falling back to source build."
            BUILD_FROM_SOURCE=true
            ;;
    esac
    
    if [ "$BUILD_FROM_SOURCE" = false ]; then
        # Get latest release info from GitHub
        echo "Fetching latest release info..."
        LATEST_RELEASE=$(curl -sL https://api.github.com/repos/hapara-fail/nx53/releases/latest)
        LATEST_VERSION=$(echo "$LATEST_RELEASE" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        
        if [ -z "$LATEST_VERSION" ]; then
            warn "Could not fetch latest release. Falling back to source build."
            BUILD_FROM_SOURCE=true
        else
            echo "Latest release: $LATEST_VERSION"
            
            # Download tarball
            TARBALL_URL="https://github.com/hapara-fail/nx53/releases/download/${LATEST_VERSION}/nx53-linux-${DOWNLOAD_ARCH}.tar.gz"
            CHECKSUM_URL="https://github.com/hapara-fail/nx53/releases/download/${LATEST_VERSION}/checksums.txt"
            
            echo "Downloading $TARBALL_URL..."
            if curl -LO "$TARBALL_URL" && curl -LO "$CHECKSUM_URL"; then
                # Verify checksum
                echo "Verifying checksum..."
                EXPECTED_CHECKSUM=$(grep "nx53-linux-${DOWNLOAD_ARCH}.tar.gz" checksums.txt | awk '{print $1}')
                ACTUAL_CHECKSUM=$(sha256sum "nx53-linux-${DOWNLOAD_ARCH}.tar.gz" | awk '{print $1}')
                
                if [ "$EXPECTED_CHECKSUM" = "$ACTUAL_CHECKSUM" ]; then
                    success "Checksum verified!"
                    
                    # Extract tarball
                    echo "Extracting files..."
                    mkdir -p nx53-extracted
                    tar xzf "nx53-linux-${DOWNLOAD_ARCH}.tar.gz" -C nx53-extracted
                    
                    BINARY_DOWNLOADED=true
                    success "Pre-built binary downloaded successfully!"
                else
                    error "Checksum verification failed!"
                    warn "Expected: $EXPECTED_CHECKSUM"
                    warn "Got: $ACTUAL_CHECKSUM"
                    warn "Falling back to source build."
                    BUILD_FROM_SOURCE=true
                fi
            else
                warn "Download failed. Falling back to source build."
                BUILD_FROM_SOURCE=true
            fi
        fi
    fi
fi

# --- Dependency Check & Installation ---

if [ "$BINARY_DOWNLOADED" = false ]; then
    info "[1/5] Checking System Dependencies..."
else
    info "[2/5] Installing System Dependencies..."
fi

# Only install build tools if building from source
if [ "$BUILD_FROM_SOURCE" = true ]; then
    if check_cmd apt-get; then
        # Debian/Ubuntu
        printf "%b\n" "${BOLD}Detected Debian/Ubuntu system.${NC}"
        printf "%b\n" "Updating package index..."
        sudo apt-get update
        printf "%b\n" "The following packages will be installed: ${BOLD}build-essential libpcap-dev pkg-config libssl-dev curl git nftables libnftnl-dev${NC}"
        printf "%b\n" "You will be prompted to confirm installation and see the size."
        sudo apt-get install build-essential libpcap-dev pkg-config libssl-dev curl git nftables libnftnl-dev < /dev/tty
    elif check_cmd dnf; then
        # Fedora/RHEL
        printf "%b\n" "${BOLD}Detected Fedora system.${NC}"
        printf "%b\n" "The following packages will be installed: ${BOLD}@development-tools libpcap-devel openssl-devel curl git nftables libnftnl-devel${NC}"
        sudo dnf install @development-tools libpcap-devel openssl-devel curl git nftables libnftnl-devel < /dev/tty
    elif check_cmd pacman; then
        # Arch Linux
        printf "%b\n" "${BOLD}Detected Arch Linux.${NC}"
        printf "%b\n" "The following packages will be installed: ${BOLD}base-devel libpcap openssl curl git nftables libnftnl${NC}"
        sudo pacman -S base-devel libpcap openssl curl git nftables libnftnl < /dev/tty
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
        
        printf "Rustup installer will run now. It will display download size and ask for confirmation.\n"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
        . "$HOME/.cargo/env"
    
    else
        success "Rust is already installed."
    fi
else
    # Only install runtime dependencies (nftables)
    if check_cmd apt-get; then
        printf "%b\n" "${BOLD}Detected Debian/Ubuntu system.${NC}"
        printf "%b\n" "Installing runtime dependencies..."
        sudo apt-get update
        sudo apt-get install -y nftables
    elif check_cmd dnf; then
        printf "%b\n" "${BOLD}Detected Fedora system.${NC}"
        sudo dnf install -y nftables
    elif check_cmd pacman; then
        printf "%b\n" "${BOLD}Detected Arch Linux.${NC}"
        sudo pacman -S --noconfirm nftables
    elif check_cmd brew; then
        printf "%b\n" "${BOLD}Detected macOS (Homebrew).${NC}"
        echo "Runtime dependencies already satisfied."
    else
        warn "Warning: Could not detect package manager."
    fi
    success "Runtime dependencies installed."
fi

# --- 2. Build or Use Downloaded Binary ---

if [ "$BINARY_DOWNLOADED" = true ]; then
    info "[3/5] Using downloaded binary..."
    echo "Skipping build step."
else
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
fi

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
if [ "$BINARY_DOWNLOADED" = true ]; then
    sudo cp nx53-extracted/bin/nx53 "$INSTALL_DIR/"
else
    sudo cp target/release/nx53 "$INSTALL_DIR/"
fi
sudo chmod +x "$INSTALL_DIR/nx53"

# Install Man Page
echo "Installing man page..."
if [ "$BINARY_DOWNLOADED" = true ]; then
    if [ -f "nx53-extracted/man/man1/nx53.1.gz" ]; then
        sudo mkdir -p /usr/share/man/man1
        sudo cp nx53-extracted/man/man1/nx53.1.gz /usr/share/man/man1/
        echo "Man page installed to /usr/share/man/man1/nx53.1.gz"
    fi
else
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
fi

# Install Completions
echo "Installing shell completions..."
if [ "$BINARY_DOWNLOADED" = true ]; then
    # Bash
    if [ -d "/usr/share/bash-completion/completions" ] && [ -f "nx53-extracted/completions/nx53.bash" ]; then
        sudo cp nx53-extracted/completions/nx53.bash /usr/share/bash-completion/completions/nx53
    elif [ -d "/etc/bash_completion.d" ] && [ -f "nx53-extracted/completions/nx53.bash" ]; then
        sudo cp nx53-extracted/completions/nx53.bash /etc/bash_completion.d/nx53
    fi

    # Zsh
    if [ -d "/usr/share/zsh/vendor-completions" ] && [ -f "nx53-extracted/completions/_nx53" ]; then
        sudo cp nx53-extracted/completions/_nx53 /usr/share/zsh/vendor-completions/
    elif [ -d "/usr/local/share/zsh/site-functions" ] && [ -f "nx53-extracted/completions/_nx53" ]; then
        sudo cp nx53-extracted/completions/_nx53 /usr/local/share/zsh/site-functions/
    fi

    # Fish
    if [ -d "/usr/share/fish/vendor_completions.d" ] && [ -f "nx53-extracted/completions/nx53.fish" ]; then
        sudo cp nx53-extracted/completions/nx53.fish /usr/share/fish/vendor_completions.d/
    fi
else
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

# Cleanup
if [ "$BINARY_DOWNLOADED" = true ]; then
    echo "Cleaning up downloaded files..."
    rm -rf nx53-extracted "nx53-linux-${DOWNLOAD_ARCH}.tar.gz" checksums.txt
fi

if [ -n "$CLONED_DIR" ]; then
    echo "Cleaning up temporary files..."
    rm -rf "$CLONED_DIR"
fi

success "Installation complete!"
