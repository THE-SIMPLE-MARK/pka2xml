#!/bin/bash

# Exit on error
set -e

echo "[*] Building pka2xml for macOS..."

# Check for required dependencies
echo "[*] Checking dependencies..."
if ! command -v brew &> /dev/null; then
    echo "[-] Homebrew not found. Please install it from https://brew.sh"
    exit 1
fi

# Determine Homebrew prefix based on architecture
if [ "$(uname -m)" = "arm64" ]; then
    BREW_PREFIX="/opt/homebrew"
else
    BREW_PREFIX="/usr/local"
fi

# Install dependencies if not present
for pkg in cryptopp re2 zlib; do
    if ! brew list $pkg &> /dev/null; then
        echo "[*] Installing $pkg..."
        brew install $pkg
    fi
done

# Verify Homebrew paths
if [ ! -d "$BREW_PREFIX/opt/cryptopp/include/cryptopp" ]; then
    echo "[-] Crypto++ headers not found in expected location"
    echo "[*] Trying to reinstall cryptopp..."
    brew reinstall cryptopp
fi

if [ ! -d "$BREW_PREFIX/opt/re2/include/re2" ]; then
    echo "[-] RE2 headers not found in expected location"
    echo "[*] Trying to reinstall re2..."
    brew reinstall re2
fi

# Build the project
echo "[*] Building project..."
make clean
make

echo "[+] Build complete! Binary located at: $(pwd)/pka2xml"
echo
echo "To install system-wide (optional):"
echo "    sudo make install-macos" 