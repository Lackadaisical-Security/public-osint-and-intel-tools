# Multi-Platform OSINT Tools

This directory contains OSINT tools implemented in various programming languages, demonstrating the versatility of intelligence gathering techniques across different platforms.

## Languages Included

### Node.js Tools
- **DNS Enumerator**: Comprehensive DNS record enumeration and subdomain discovery
- **Web Scraper**: Extract emails, phone numbers, and social media links from websites

### C Tools
- **Port Scanner**: Fast TCP port scanning with service detection
- **IP Tracer**: Trace route and gather IP information
- **DNS Resolver**: Low-level DNS resolution tool

### C++ Tools
- **HTTP Header Analyzer**: Analyze HTTP headers for security and technology detection
- **Subdomain Finder**: Advanced subdomain enumeration with threading

### Assembly (x64) Tools
- **Network Probe**: Low-level network connectivity testing
- Demonstrates system programming for network operations

### .NET Tools
- **Domain Analyzer**: Comprehensive domain analysis with async operations
- **Email Validator**: Email validation and intelligence gathering
- **WHOIS Lookup**: Domain and IP WHOIS information retrieval

## Building and Running

### Node.js
```bash
cd nodejs
npm install
node dns-enum.js example.com
node web-scraper.js https://example.com
```

### C/C++
```bash
# Windows with MinGW
cd c
make all

# Linux/Mac
cd c
make all
```

### Assembly
```bash
# Windows
cd asm
build.bat

# Linux (requires NASM)
nasm -f elf64 network_probe.asm -o network_probe.o
ld network_probe.o -o network_probe
```

### .NET
```bash
cd dotnet
dotnet build
dotnet run -- -d example.com
```

## Security Notice

These tools are provided for educational and ethical security research purposes only. Always ensure you have permission before scanning or gathering intelligence on any target.

## License

All tools are licensed under the Lackadaisical Security Public License. See the main LICENSE file for details.

---
Developed by Lackadaisical Security  
https://lackadaisical-security.com/
