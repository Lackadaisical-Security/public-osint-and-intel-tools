@echo off
REM Build script for assembly tools - Lackadaisical Security

echo Building Assembly OSINT Tools...

REM Assemble and link network_probe
nasm -f win64 network_probe.asm -o network_probe.obj
link network_probe.obj /subsystem:console /entry:main kernel32.lib ws2_32.lib /out:network_probe.exe

REM Clean up object files
del *.obj

echo Build complete!
