#!/usr/bin/env bash
# ==============================================================================
# SentryIP One-Line Automated Installer for Linux and macOS
# Usage: curl -fsSL https://raw.githubusercontent.com/Samore141025/SentryIP/main/install.sh | bash
# ==============================================================================

set -e

echo -e "\033[1;32m"
cat << "EOF"
   ███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗██╗██████╗ 
   ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝██║██╔══██╗
   ███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝ ██║██████╔╝
   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝  ██║██╔═══╝ 
   ███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║   ██║██║     
   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝╚═╝     
EOF
echo -e "\033[0m"
echo -e "\033[1;36m>>> Installing SentryIP Autonomous SOC Threat Intel Agent...\033[0m"

INSTALL_DIR="$HOME/.sentryip-app"

# Check Python 3
if ! command -v python3 &>/dev/null; then
    echo -e "\033[1;31mError: Python 3.11+ is required but not installed.\033[0m"
    exit 1
fi

# Clone or update
if [ -d "$INSTALL_DIR" ]; then
    echo "Updating existing installation in $INSTALL_DIR..."
    git -C "$INSTALL_DIR" pull --quiet
else
    echo "Cloning SentryIP repository..."
    git clone --quiet https://github.com/Samore141025/SentryIP.git "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"

# Set up virtual environment
echo "Configuring virtual environment..."
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip --quiet
pip install -e . --quiet

# Symlink executable to /usr/local/bin or ~/.local/bin
BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"
ln -sf "$INSTALL_DIR/.venv/bin/sentryip" "$BIN_DIR/sentryip"

# Add to PATH if not already present
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> "$HOME/.bashrc"
    echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> "$HOME/.zshrc" 2>/dev/null || true
fi

echo -e "\033[1;32m✔ SentryIP successfully installed!\033[0m"
echo -e "Run \033[1;33msentryip\033[0m to launch the interactive SOC threat analyst."
echo -e "Run \033[1;33msentryip --keys\033[0m to configure your API keys."
