#!/bin/bash

# Build script for all OSINT tools
# Lackadaisical Security - https://lackadaisical-security.com/

echo "Building OSINT Tools - Multi-Platform Edition"
echo "============================================="

# Build C tools
echo "[*] Building C tools..."
cd c
make clean
make all
cd ..

# Build C++ tools
echo "[*] Building C++ tools..."
cd cpp
make clean
make all
cd ..

# Build Assembly tools
echo "[*] Building Assembly tools..."
cd asm
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    nasm -f elf64 network_probe.asm -o network_probe.o
    ld network_probe.o -o network_probe
elif [[ "$OSTYPE" == "darwin"* ]]; then
    nasm -f macho64 network_probe.asm -o network_probe.o
    ld -o network_probe network_probe.o -lSystem
fi
cd ..

# Build .NET tools
echo "[*] Building .NET tools..."
cd dotnet
dotnet build --configuration Release
cd ..

# Setup Node.js tools
echo "[*] Setting up Node.js tools..."
cd nodejs
npm install
cd ..

echo ""
echo "Build complete! All tools are ready to use."
echo "See README.md for usage instructions."
