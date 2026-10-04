#!/usr/bin/env bash
set -e

echo ">>> [Ostadix Bootstrap] Step 1: Installing the Nix daemon..."
if ! command -v nix &> /dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf -L \
        https://install.determinate.systems/nix \
        | sh -s -- install --no-confirm
    # Source the daemon so we can use nix immediately
    . /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
    echo "  ✓ Nix installed"
else
    echo "  ✓ Nix already present, skipping"
fi

echo ">>> [Ostadix Bootstrap] Step 2: Detecting OS and architecture..."
OS="$(uname -s)"
ARCH="$(uname -m)"

if [[ "$OS" == "Darwin" && "$ARCH" == "arm64" ]]; then
    HM_TARGET="ustad@mac-arm"
elif [[ "$OS" == "Darwin" ]]; then
    HM_TARGET="ustad@mac-intel"
else
    HM_TARGET="ustad@linux"
fi

echo "  ✓ Target profile: $HM_TARGET"

echo ">>> [Ostadix Bootstrap] Step 3: Applying Home Manager configuration..."
nix run github:nix-community/home-manager -- \
    switch --flake "github:YourUsername/ostadix-core#$HM_TARGET"

echo ""
echo "  ╔═══════════════════════════════════════════╗"
echo "  ║   Ostadix Shell Engine is now installed   ║"
echo "  ║   Type: ostadix                           ║"
echo "  ║   Or:   ostadix shell '(python3 rustc)'   ║"
echo "  ╚═══════════════════════════════════════════╝"
