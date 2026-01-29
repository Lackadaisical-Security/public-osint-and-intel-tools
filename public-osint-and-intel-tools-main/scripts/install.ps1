# Installation script for OSINT Tools - Windows
# Lackadaisical Security - https://lackadaisical-security.com/

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  OSINT Tools Installer - Lackadaisical Security" -ForegroundColor Cyan
Write-Host "  https://lackadaisical-security.com/" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Host "[-] This script should be run as Administrator for best results" -ForegroundColor Yellow
}

# Function to check if a command exists
function Test-Command {
    param($Command)
    try {
        if (Get-Command $Command -ErrorAction Stop) {
            Write-Host "[+] $Command is installed" -ForegroundColor Green
            return $true
        }
    } catch {
        Write-Host "[-] $Command is not installed" -ForegroundColor Red
        return $false
    }
}

Write-Host "[*] Checking prerequisites..." -ForegroundColor Yellow

# Python tools
if (Test-Command python) {
    Write-Host "[*] Installing Python dependencies..." -ForegroundColor Yellow
    python -m pip install --upgrade pip
    python -m pip install -r requirements.txt
} elseif (Test-Command python3) {
    Write-Host "[*] Installing Python dependencies..." -ForegroundColor Yellow
    python3 -m pip install --upgrade pip
    python3 -m pip install -r requirements.txt
}

# Node.js tools
if (Test-Command node) {
    Write-Host "[*] Installing Node.js dependencies..." -ForegroundColor Yellow
    Push-Location tools-multiplatform\nodejs
    npm install
    Pop-Location
}

# .NET tools
if (Test-Command dotnet) {
    Write-Host "[*] Building .NET tools..." -ForegroundColor Yellow
    Push-Location tools-multiplatform\dotnet
    dotnet build --configuration Release
    Pop-Location
}

# Check for C/C++ compiler
$hasCompiler = $false
if (Test-Command gcc) {
    $hasCompiler = $true
} elseif (Test-Command cl) {
    $hasCompiler = $true
}

if ($hasCompiler) {
    Write-Host "[*] Building native tools..." -ForegroundColor Yellow
    Push-Location tools-multiplatform
    & .\build-all.bat
    Pop-Location
}

# Create directories
Write-Host "[*] Creating directories..." -ForegroundColor Yellow
$directories = @("output", "wordlists", "logs")
foreach ($dir in $directories) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
        Write-Host "[+] Created directory: $dir" -ForegroundColor Green
    }
}

# Download wordlists
Write-Host "[*] Downloading wordlists..." -ForegroundColor Yellow
$wordlistUrl = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt"
$wordlistPath = "wordlists\subdomains-top1million-5000.txt"

if (-not (Test-Path $wordlistPath)) {
    try {
        Invoke-WebRequest -Uri $wordlistUrl -OutFile $wordlistPath
        Write-Host "[+] Downloaded subdomain wordlist" -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed to download wordlist: $_" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "[+] Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Usage examples:" -ForegroundColor Cyan
Write-Host "  Python:  python osint_cli.py -d example.com"
Write-Host "  Node.js: node tools-multiplatform\nodejs\dns-enum.js example.com"
Write-Host "  .NET:    dotnet run --project tools-multiplatform\dotnet -- -d example.com"
Write-Host ""
Write-Host "For more information, see README.md" -ForegroundColor Yellow
