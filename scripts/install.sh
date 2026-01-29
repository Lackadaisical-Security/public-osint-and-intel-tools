#!/bin/bash

# Installation script for OSINT Tools
# Lackadaisical Security - https://lackadaisical-security.com/

set -e

echo "================================================"
echo "  OSINT Tools Installer - Lackadaisical Security"
echo "  https://lackadaisical-security.com/"
echo "================================================"
echo

# Check OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    echo "[-] Unsupported OS: $OSTYPE"
    exit 1
fi

echo "[*] Detected OS: $OS"

# Check for required tools
echo "[*] Checking prerequisites..."

check_command() {
    if ! command -v $1 &> /dev/null; then
        echo "[-] $1 is not installed"
        return 1
    else
        echo "[+] $1 is installed"
        return 0
    fi
}

# Python tools
if check_command python3; then
    echo "[*] Installing Python dependencies..."
    pip3 install -r requirements.txt
fi

# Node.js tools
if check_command node; then
    echo "[*] Installing Node.js dependencies..."
    cd tools-multiplatform/nodejs
    npm install
    cd ../..
fi

# .NET tools
if check_command dotnet; then
    echo "[*] Building .NET tools..."
    cd tools-multiplatform/dotnet
    dotnet build --configuration Release
    cd ../..
fi

# C/C++ tools
if check_command gcc && check_command g++; then
    echo "[*] Building C/C++ tools..."
    cd tools-multiplatform
    
    # Build C tools
    cd c
    make clean && make all
    cd ..
    
    # Build C++ tools
    cd cpp
    make clean && make all
    cd ../..
fi

# Assembly tools (Linux only)
if [[ "$OS" == "linux" ]] && check_command nasm; then
    echo "[*] Building Assembly tools..."
    cd tools-multiplatform/asm
    make clean && make all
    cd ../..
fi

# Create directories
echo "[*] Creating directories..."
mkdir -p output
mkdir -p wordlists
mkdir -p logs

# Download common wordlists
echo "[*] Downloading wordlists..."
if [ ! -f "wordlists/subdomains-top1million-5000.txt" ]; then
    curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt \
        -o wordlists/subdomains-top1million-5000.txt
fi

# Set permissions
echo "[*] Setting permissions..."
find . -name "*.py" -exec chmod +x {} \;
find . -name "*.js" -exec chmod +x {} \;
find . -name "*.sh" -exec chmod +x {} \;

echo
echo "[+] Installation complete!"
echo
echo "Usage examples:"
echo "  Python:  python3 osint_cli.py -d example.com"
echo "  Node.js: node tools-multiplatform/nodejs/dns-enum.js example.com"
echo "  .NET:    dotnet run --project tools-multiplatform/dotnet -- -d example.com"
echo
echo "For more information, see README.md"
