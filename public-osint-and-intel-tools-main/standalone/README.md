# Standalone OSINT Scripts

This directory contains standalone OSINT scripts that require no compilation or external dependencies. Each script uses only the standard library of its respective language.

## Available Scripts

### Python Scripts

#### domain_recon.py
Comprehensive domain reconnaissance tool.
```bash
python3 domain_recon.py example.com
```
Features:
- DNS record enumeration
- SSL certificate analysis
- HTTP header inspection
- Basic port scanning
- Subdomain discovery

#### email_hunter.py
Email discovery and validation tool.
```bash
python3 email_hunter.py example.com
```
Features:
- Pattern-based email generation
- Website scraping for emails
- Email domain verification
- Common email format detection

### Node.js Scripts

#### portscanner.js
Fast asynchronous port scanner.
```bash
node portscanner.js example.com 1 1000 50
```
Features:
- Concurrent port scanning
- Service detection
- Custom port ranges
- Configurable thread count

### PowerShell Scripts

#### dns_lookup.ps1
Windows DNS reconnaissance tool.
```powershell
.\dns_lookup.ps1 -Domain example.com -OutputFile results.json
```
Features:
- Complete DNS record enumeration
- Subdomain discovery
- Reverse DNS lookups
- SPF/DMARC detection

### Bash Scripts

#### whois_lookup.sh
WHOIS and DNS information gathering.
```bash
./whois_lookup.sh example.com output.txt
```
Features:
- WHOIS data parsing
- DNS record lookup
- Related domain discovery
- Contact email extraction

### Ruby Scripts

#### ip_geolocator.rb
IP geolocation using multiple APIs.
```ruby
ruby ip_geolocator.rb 8.8.8.8
```
Features:
- Multiple API sources
- Hostname resolution
- Coordinate mapping
- ISP/Organization info

## Requirements

- **Python**: Python 3.6+
- **Node.js**: Node.js 12+
- **PowerShell**: PowerShell 5.0+ (Windows)
- **Bash**: Bash 4+ with standard tools (dig, whois)
- **Ruby**: Ruby 2.5+

## Usage Notes

1. **No compilation required** - All scripts are interpreted
2. **No external dependencies** - Uses only standard libraries
3. **Cross-platform** - Most scripts work on multiple operating systems
4. **Output formats** - All scripts can save results to JSON/text files

## Security Considerations

- Always obtain permission before scanning targets
- Be aware of rate limits when using external APIs
- Some scripts may trigger security alerts
- Use responsibly and ethically

## Contributing

To add a new standalone script:
1. Use only standard library functions
2. Include comprehensive error handling
3. Add progress indicators for long operations
4. Support both console output and file saving
5. Include the Lackadaisical Security banner

---
Developed by Lackadaisical Security  
https://lackadaisical-security.com/
