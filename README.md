# Public OSINT & Intelligence Gathering Tools

A comprehensive Python-based toolkit for Open Source Intelligence (OSINT) gathering and reconnaissance. This toolkit provides various modules for gathering intelligence from public sources.

## Features

### 🌐 Domain Intelligence
- WHOIS information lookup
- DNS record enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME)
- Subdomain discovery
- IP address resolution

### 🔍 IP Intelligence
- Reverse DNS lookup
- Geolocation information
- ASN (Autonomous System Number) details
- ISP information

### 📧 Email Intelligence
- Email format validation
- MX record verification
- Disposable email detection
- Social media profile discovery

### 🕷️ Web Scraping Intelligence
- Email extraction from websites
- Phone number extraction
- Social media link discovery
- Technology stack detection
- Meta information extraction
- Internal/external link analysis

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/public-osint-and-intel-tools.git
cd public-osint-and-intel-tools-main
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

3. (Optional) Create a `.env` file for API keys:
```env
SHODAN_API_KEY=your_shodan_api_key
TWITTER_API_KEY=your_twitter_api_key
TWITTER_API_SECRET=your_twitter_api_secret
TWITTER_ACCESS_TOKEN=your_twitter_access_token
TWITTER_ACCESS_SECRET=your_twitter_access_secret
```

## Usage

### Command Line Interface

```bash
# Domain intelligence
python osint_cli.py -d example.com

# IP intelligence
python osint_cli.py -i 8.8.8.8

# Email intelligence
python osint_cli.py -e user@example.com

# Web scraping
python osint_cli.py -w https://example.com

# Save results to file
python osint_cli.py -d example.com -o results.json
```

### Python API

```python
from tools.domain_intel import DomainIntel
from tools.ip_intel import IPIntel
from tools.email_intel import EmailIntel
from tools.web_scraper import WebScraper

# Domain intelligence
domain_intel = DomainIntel()
results = domain_intel.gather_intel("example.com")

# IP intelligence
ip_intel = IPIntel()
results = ip_intel.gather_intel("8.8.8.8")

# Email intelligence
email_intel = EmailIntel()
results = email_intel.gather_intel("user@example.com")

# Web scraping
scraper = WebScraper()
results = scraper.scrape_intel("https://example.com")
```

## Ethical Use

This toolkit is designed for:
- Security research
- Bug bounty hunting
- Penetration testing (with permission)
- Educational purposes
- Investigating your own digital footprint

**Important**: Always ensure you have permission before gathering intelligence on any target. Respect privacy laws and terms of service.

## Legal Disclaimer

This tool is provided for educational and ethical purposes only. Users are responsible for complying with all applicable laws and regulations. The authors assume no liability for misuse of this tool.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
