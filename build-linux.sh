#!/bin/bash

# Exit on error
set -e

echo "[*] Building pka2xml for Linux..."

# Check for required dependencies
echo "[*] Checking dependencies..."
DEPS="g++ make zlib1g-dev libcrypto++-dev libre2-dev"
PKG_MANAGER=""

if command -v apt &> /dev/null; then
    PKG_MANAGER="apt"
elif command -v dnf &> /dev/null; then
    PKG_MANAGER="dnf"
elif command -v yum &> /dev/null; then
    PKG_MANAGER="yum"
elif command -v pacman &> /dev/null; then
    PKG_MANAGER="pacman"
    DEPS="gcc make zlib cryptopp re2"  # Adjust package names for Arch Linux
else
    echo "[-] No supported package manager found (apt, dnf, yum, or pacman)"
    exit 1
fi

# Install dependencies
echo "[*] Installing dependencies using $PKG_MANAGER..."
if [ "$PKG_MANAGER" = "pacman" ]; then
    sudo pacman -Sy --needed $DEPS
else
    sudo $PKG_MANAGER update
    sudo $PKG_MANAGER install -y $DEPS
fi

# Build the project
echo "[*] Building project..."
make clean
make

echo "[+] Build complete! Binary located at: $(pwd)/pka2xml"
echo
echo "To install system-wide (optional):"
echo "    sudo make install" 