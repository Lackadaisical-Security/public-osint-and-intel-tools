@echo off
REM Build script for all OSINT tools - Windows
REM Lackadaisical Security - https://lackadaisical-security.com/

echo Building OSINT Tools - Multi-Platform Edition
echo =============================================

REM Build C tools
echo [*] Building C tools...
cd c
make clean
make all
cd ..

REM Build C++ tools
echo [*] Building C++ tools...
cd cpp
make clean
make all
cd ..

REM Build Assembly tools
echo [*] Building Assembly tools...
cd asm
call build.bat
cd ..

REM Build .NET tools
echo [*] Building .NET tools...
cd dotnet
dotnet build --configuration Release
cd ..

REM Setup Node.js tools
echo [*] Setting up Node.js tools...
cd nodejs
npm install
cd ..

echo.
echo =============================================
echo Build Summary:
echo =============================================
echo.

REM Check if builds were successful
if exist "c\port_scanner.exe" (
    echo [+] C tools: BUILD SUCCESS
) else (
    echo [-] C tools: BUILD FAILED
)

if exist "cpp\http_header_analyzer.exe" (
    echo [+] C++ tools: BUILD SUCCESS
) else (
    echo [-] C++ tools: BUILD FAILED
)

if exist "asm\network_probe.exe" (
    echo [+] Assembly tools: BUILD SUCCESS
) else (
    echo [-] Assembly tools: BUILD FAILED
)

if exist "dotnet\bin\Release\net6.0\OSINTTools.exe" (
    echo [+] .NET tools: BUILD SUCCESS
) else (
    echo [-] .NET tools: BUILD FAILED
)

if exist "nodejs\node_modules" (
    echo [+] Node.js tools: SETUP SUCCESS
) else (
    echo [-] Node.js tools: SETUP FAILED
)

echo.
echo =============================================
echo Build complete! All tools are ready to use.
echo See README.md for usage instructions.
echo.
echo Developed by Lackadaisical Security
echo https://lackadaisical-security.com/
echo =============================================
pause
