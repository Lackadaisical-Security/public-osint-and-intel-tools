# Security Policy

## Overview

Security is paramount for OSINT tools. This document outlines our security practices, vulnerability reporting, and operational security guidelines.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |
| < 1.0   | :x:                |

**We only support the latest main branch.** Security fixes are not backported to older versions.

## Reporting Vulnerabilities

### Security Issues

**DO NOT** open public GitHub issues for security vulnerabilities.

**Contact:**
- **Email**: lackadaisicalresearch@pm.me
- **PGP**: Available on request
- **XMPP+OTR**: thelackadaisicalone@xmpp.jp

### What to Include

Provide detailed information:
1. **Description**: Clear explanation of the vulnerability
2. **Impact**: What an attacker could achieve
3. **Affected Components**: Which files/modules are vulnerable
4. **Proof of Concept**: Steps to reproduce (code/commands)
5. **Suggested Fix**: If you have one
6. **CVE**: If already assigned

**Example:**
```
Subject: [SECURITY] Command Injection in domain_recon.py

Description:
The domain_recon.py tool is vulnerable to command injection through
the domain parameter when using the whois lookup function.

Impact:
An attacker can execute arbitrary shell commands by providing a
specially crafted domain name.

Proof of Concept:
python standalone/domain_recon.py "example.com; cat /etc/passwd"

Suggested Fix:
Use subprocess with shell=False and proper argument escaping.
```

### Response Timeline

- **24 hours**: Acknowledge receipt
- **72 hours**: Initial assessment
- **7 days**: Provide fix or mitigation
- **30 days**: Public disclosure (coordinated)

### Bounty Program

**Current Status**: No formal bug bounty program.

However, we recognize quality security research:
- Hall of fame listing
- Public acknowledgment (if desired)
- Swag (stickers, shirts) for critical findings

## Security Best Practices

### For Users

#### Credential Management
```python
# NEVER hardcode credentials
api_key = "YOUR_API_KEY_HERE"  # ❌ WRONG

# Use environment variables
import os
api_key = os.environ.get('SHODAN_API_KEY')  # ✓ CORRECT

# Use encrypted credential storage
from privacy.secure_credentials import SecureCredentialStore
store = SecureCredentialStore()
store.unlock()
api_key = store.get('SHODAN_API_KEY')  # ✓ BETTER
```

#### Anonymity & OPSEC
```python
# Use Tor for sensitive operations
from privacy.tor_proxy import TorSession

session = TorSession()
response = session.get('https://target.com')

# Use proxy rotation
from privacy.proxy_rotation import ProxyRotator

rotator = ProxyRotator()
rotator.add_proxy('socks5', '127.0.0.1', 9050)
proxy = rotator.get_next_proxy()

# Obfuscate requests
from privacy.request_obfuscation import ObfuscatedSession

session = ObfuscatedSession()
response = session.get('https://target.com')
```

#### Input Validation
```python
# ALWAYS validate input
import validators

def lookup_domain(domain):
    if not validators.domain(domain):
        raise ValueError(f"Invalid domain: {domain}")
    # Proceed with lookup
```

#### Rate Limiting
```python
# Implement rate limiting
import time

def make_requests(targets):
    for target in targets:
        process_target(target)
        time.sleep(1)  # Avoid hammering servers
```

### For Contributors

#### Code Security Checklist

**Before submitting code:**
- [ ] Input validation on all user-provided data
- [ ] No SQL injection vulnerabilities
- [ ] No command injection vulnerabilities
- [ ] No path traversal vulnerabilities
- [ ] No XSS vulnerabilities (if generating HTML)
- [ ] No hardcoded credentials
- [ ] HTTPS for external connections
- [ ] Proper error handling (no stack trace leaks)
- [ ] Rate limiting implemented
- [ ] Secure credential storage
- [ ] No secrets in commit history

#### Dependency Security

**Check dependencies for vulnerabilities:**
```bash
# Install safety
pip install safety

# Check for known vulnerabilities
safety check

# Update dependencies
pip list --outdated
pip install --upgrade package-name
```

**Always specify exact versions:**
```
# requirements.txt
requests==2.31.0      # ✓ CORRECT
requests>=2.31.0      # ❌ WRONG (allows vulnerable versions)
```

#### Secret Scanning

**Before committing:**
```bash
# Check for secrets
git diff | grep -i "api_key\|password\|secret\|token"

# Use git-secrets
git secrets --scan

# Check commit history
git log -p | grep -i "api_key\|password"
```

**If secrets are committed:**
```bash
# 1. Rotate the exposed credentials immediately
# 2. Remove from git history
git filter-branch --force --index-filter \
  'git rm --cached --ignore-unmatch path/to/file' \
  --prune-empty --tag-name-filter cat -- --all

# 3. Force push (DANGEROUS - coordinate with team)
git push --force --all
```

## Threat Model

### Assumptions

**We assume:**
- Users have legitimate authorization for OSINT operations
- Users understand OPSEC and operational security
- Users follow legal and ethical guidelines
- Users secure their own systems and credentials

**We do NOT assume:**
- Adversaries cannot access source code (it's open source)
- Users are security experts (we provide guidance)
- All dependencies are trustworthy (we audit critical ones)

### Threat Actors

**Potential adversaries:**
1. **Targets**: Organizations being investigated may detect activities
2. **Law Enforcement**: Unauthorized use could result in legal action
3. **Malicious Users**: Bad actors could abuse tools for harmful purposes
4. **Supply Chain**: Compromised dependencies or malicious contributors

### Security Controls

**Implemented:**
- Encrypted credential storage
- Tor/proxy integration for anonymity
- Request obfuscation and fingerprint randomization
- Rate limiting to avoid detection
- Input validation to prevent injection attacks
- Secure coding practices

**Planned:**
- Automated security scanning (CodeQL, Bandit)
- Dependency vulnerability monitoring
- Code signing for releases
- Security audit logging

## Known Security Considerations

### Anonymity Limitations

**Tor/VPN cannot protect against:**
- Browser fingerprinting (mitigate with request obfuscation)
- DNS leaks (use DNS leak checker)
- WebRTC leaks (disable in browser)
- Time-based correlation attacks
- Operational security mistakes

**Best practices:**
- Use Tails or Whonix for maximum anonymity
- Never reuse identities across operations
- Compartmentalize activities
- Verify anonymity before sensitive operations

### Data Retention

**What we store:**
- Nothing. Tools run locally, no data sent to us.

**What you should store:**
- Encrypted intelligence data
- Audit logs of operations
- Sanitized results (remove PII when sharing)

**What you shouldn't store:**
- Unencrypted credentials
- Raw intelligence with PII
- Logs on shared systems
- Data in version control

### Legal Compliance

**Know the law:**
- **CFAA (US)**: Unauthorized access is illegal
- **GDPR (EU)**: Data protection regulations
- **CCPA (California)**: Consumer privacy rights
- **ECPA (US)**: Electronic communications privacy
- **Export Controls**: Some tools may be restricted

**Always:**
- Obtain written authorization before operations
- Document scope and limitations
- Respect data protection laws
- Follow responsible disclosure
- Consult legal counsel for sensitive operations

## Export Control & International Compliance

### U.S. Export Administration Regulations (EAR)

This software contains security analysis and cryptographic capabilities that may be subject to U.S. export controls.

**Classification Information:**
- **ECCN**: Potentially 5D002 (Information Security Software)
- **License Exception**: May qualify for TSU (Technology and Software - Unrestricted) under EAR §740.13(e)
- **Controlled Capabilities**: Encryption, penetration testing, network security analysis

### Restricted Destinations

**The following countries and regions are subject to U.S. sanctions and export restrictions:**

**Comprehensive Sanctions (as of 2026):**
- 🚫 **Cuba** - Comprehensive trade embargo
- 🚫 **Iran** - Comprehensive sanctions program
- 🚫 **North Korea (DPRK)** - Comprehensive sanctions
- 🚫 **Syria** - Comprehensive sanctions
- 🚫 **Crimea, Donetsk, and Luhansk regions of Ukraine** - Regional sanctions

**Other Restricted Parties:**
- Entities on the Denied Persons List
- Entities on the Entity List
- Specially Designated Nationals (SDN) List
- Unverified List
- Military End-User (MEU) List

**Verify current restrictions:**
- **BIS**: https://www.bis.doc.gov/index.php/policy-guidance/lists-of-parties-of-concern
- **OFAC**: https://ofac.treasury.gov/specially-designated-nationals-and-blocked-persons-list-sdn-human-readable-lists
- **State Department**: https://www.pmddtc.state.gov/

### User Export Control Obligations

**Before using this software, you must:**

1. **Verify Location Compliance**
   - Ensure you are not located in a sanctioned country
   - Verify your organization is not on a denied party list
   - Check end-user screening requirements

2. **Determine Export Classification**
   - Understand the software's ECCN classification
   - Determine if a license is required for your use case
   - Consult with export compliance specialists if needed

3. **Screen Parties**
   - Screen all parties involved against denied party lists
   - Maintain records of screening activities
   - Implement ongoing monitoring procedures

4. **Document Compliance**
   - Maintain export compliance records
   - Document authorization and screening
   - Retain records per regulatory requirements (typically 5 years)

5. **Obtain Necessary Authorizations**
   - Apply for export licenses if required
   - Obtain written authorization for all intelligence operations
   - Ensure compliance with destination country import laws

### International Users

**Non-U.S. users must also comply with:**

**European Union:**
- EU Dual-Use Regulation (2021/821)
- General Data Protection Regulation (GDPR)
- Network and Information Security (NIS) Directive
- Local cybersecurity laws

**United Kingdom:**
- Export Control Order 2008
- UK Strategic Export Controls
- Investigatory Powers Act 2016

**Canada:**
- Export and Import Permits Act
- Defence Production Act
- Criminal Code provisions on unauthorized computer use

**Australia:**
- Defence Trade Controls Act 2012
- Export Control List
- Cybercrime Act

**Asia-Pacific:**
- Wassenaar Arrangement participant countries
- Local encryption import/export regulations
- Cybersecurity and intelligence laws

**Middle East & Africa:**
- Local encryption regulations (many countries restrict or ban encryption)
- Intelligence gathering prohibitions
- Cybersecurity laws

### Prohibited End-Uses

**This software must NOT be used in connection with:**
- ❌ Nuclear weapons or nuclear explosive devices
- ❌ Chemical or biological weapons
- ❌ Missile systems (rocket systems, unmanned aerial vehicles)
- ❌ Military intelligence against allied nations
- ❌ Terrorism or terrorist organizations
- ❌ Human rights violations
- ❌ Proliferation of weapons of mass destruction

### Deemed Export Considerations

**"Deemed Export" occurs when:**
- Technology or source code is disclosed to foreign nationals
- Within the U.S. or abroad
- Including remote access by foreign nationals

**Compliance requirements:**
- Screen foreign nationals against denied party lists
- Determine if technology release requires authorization
- Maintain records of technology transfers
- Implement access controls for restricted technology

### Encryption Technology Notice

**This software includes encryption capabilities subject to export controls:**

**Included Cryptographic Functions:**
- Secure credential storage (encryption at rest)
- Secure logging (encrypted audit trails)
- TLS/SSL certificate analysis
- Encrypted communication channels
- Cryptographic hashing and signing

**Export Control Status:**
- May qualify for License Exception ENC or TSU
- Users must verify their specific use case
- Commercial encryption may require CCATS registration
- Open-source availability does NOT eliminate export obligations

**International Users:**
Many countries regulate encryption import and use. Verify local laws before importing or using encryption technology.

### Sanctions Screening Procedures

**Recommended screening process:**

1. **Pre-Use Screening**
   ```bash
   # Example: Check if IP address is in sanctioned country
   # (This is illustrative - use proper screening tools)
   curl -s "https://ipapi.co/IP_ADDRESS/json/" | jq '.country'
   ```

2. **Regular Monitoring**
   - Subscribe to BIS and OFAC updates
   - Review sanctioned countries list quarterly
   - Update screening procedures as regulations change

3. **Maintain Records**
   - Document all screening activities
   - Retain records for minimum 5 years
   - Include date, methodology, and results

### Export Violation Penalties

**Violations of export control laws can result in:**

**Civil Penalties:**
- Up to $300,000 per violation (or twice the value of the transaction)
- Denial of export privileges
- Seizure of goods

**Criminal Penalties:**
- Up to $1,000,000 in fines (per violation)
- Up to 20 years imprisonment
- Forfeiture of property

**Corporate Penalties:**
- Debarment from government contracts
- Reputation damage
- Loss of export privileges
- Enhanced compliance monitoring

### Compliance Resources

**U.S. Government Agencies:**

**Bureau of Industry and Security (BIS)**
- Website: https://www.bis.doc.gov/
- Email: exportcontrol@bis.doc.gov
- Phone: +1 (202) 482-4811
- Export Counseling: https://www.bis.doc.gov/index.php/about-bis/export-counseling

**Office of Foreign Assets Control (OFAC)**
- Website: https://ofac.treasury.gov/
- Hotline: +1 (800) 540-6322
- Email: ofac.feedback@treasury.gov

**Directorate of Defense Trade Controls (DDTC)**
- Website: https://www.pmddtc.state.gov/
- Email: DDTCResponseTeam@state.gov
- Phone: +1 (202) 663-1282

**Industry Resources:**
- Wassenaar Arrangement: https://www.wassenaar.org/
- Export Compliance Training Institute: https://www.exportuniversity.com/
- Bureau of Industry and Security Webinars: https://www.bis.doc.gov/index.php/forms-documents/regulations-docs/2326-general-webinar-schedule/file

### Export Control Checklist

**Before using or distributing this software:**

- [ ] Verified not located in sanctioned country
- [ ] Screened all parties against denied party lists
- [ ] Determined export classification (ECCN)
- [ ] Verified no license required (or obtained license)
- [ ] Reviewed prohibited end-uses
- [ ] Documented compliance activities
- [ ] Obtained legal counsel review (if needed)
- [ ] Implemented ongoing monitoring procedures
- [ ] Trained personnel on export compliance
- [ ] Established record-keeping procedures

### Disclaimer

**IMPORTANT LEGAL DISCLAIMER:**

The export control information provided in this document is for general informational purposes only and does not constitute legal advice. Export control laws and regulations are complex and subject to change.

**The maintainers:**
- Are not export control attorneys or licensed advisors
- Make no representations regarding the accuracy or completeness of this information
- Accept no liability for export control violations or penalties
- Strongly recommend consulting with qualified legal counsel and export compliance professionals

**Users are solely responsible for:**
- Determining their export control obligations
- Obtaining necessary licenses and authorizations
- Complying with all applicable laws and regulations
- Staying informed of regulatory changes
- Implementing appropriate compliance programs

**For official guidance, contact the relevant government agencies listed above.**

**Last Updated:** January 2026  
**Review Frequency:** Quarterly or when regulations change

## Compliance & Certifications

### Standards

**We follow:**
- OWASP Top 10 (web application security)
- CWE Top 25 (common weakness enumeration)
- NIST Cybersecurity Framework
- SANS Critical Security Controls

### Audits

**Current status:**
- No formal third-party audit
- Community review via open source
- Automated security scanning planned

**Future plans:**
- Annual security audit
- Penetration testing of critical components
- SOC 2 Type II (if commercially deployed)

## Incident Response

### If Compromise Suspected

**Immediate actions:**
1. **Isolate**: Disconnect affected systems
2. **Assess**: Determine scope and impact
3. **Notify**: Contact maintainers immediately
4. **Preserve**: Save logs and evidence
5. **Remediate**: Apply fixes
6. **Review**: Post-incident analysis

### Disclosure Policy

**Our commitments:**
- Acknowledge vulnerabilities within 24 hours
- Provide fixes within 7 days for critical issues
- Coordinate disclosure with researchers
- Credit researchers (unless anonymity requested)
- Publish CVEs for significant vulnerabilities

## Security Hall of Fame

**Contributors who have responsibly disclosed vulnerabilities:**

*Currently empty - be the first!*

---

**To be added:**
- Name (or handle)
- Date of disclosure
- Vulnerability type
- Severity level

## Resources

### Security Tools
- **Bandit**: Python security linter
- **Safety**: Dependency vulnerability scanner
- **CodeQL**: Semantic code analysis
- **Git-secrets**: Prevent committing secrets
- **OWASP ZAP**: Web application security scanner

### Educational Resources
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [SANS Security Resources](https://www.sans.org/security-resources/)
- [Krebs on Security](https://krebsonsecurity.com/)

### Anonymity & OPSEC
- [Tor Project](https://www.torproject.org/)
- [TAILS](https://tails.boum.org/)
- [Whonix](https://www.whonix.org/)
- [EFF Surveillance Self-Defense](https://ssd.eff.org/)

## Contact

**Security Team:**
- **Email**: lackadaisicalresearch@pm.me
- **PGP**: Request via email
- **XMPP+OTR**: thelackadaisicalone@xmpp.jp

**General Contact:**
- **GitHub**: https://github.com/Lackadaisical-Security
- **Website**: https://lackadaisical-security.com

---

**Remember: Security is a process, not a product. Stay vigilant.**

**Copyright © 2025-2026 Lackadaisical Security. All rights reserved.**
