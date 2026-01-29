# OPSEC Guide for OSINT Operations

## Introduction

**Operational Security (OPSEC) is critical for intelligence gathering.** Poor OPSEC can compromise investigations, reveal your identity, and create legal liability.

This guide provides practical OPSEC procedures for using these OSINT tools safely and effectively.

## Threat Model

### What You're Protecting

**Your identity and activities:**
- Real IP address
- Physical location
- Browser fingerprint
- Search patterns
- Tools and techniques
- Investigation targets

**Your data:**
- Collected intelligence
- API keys and credentials
- Operational logs
- Communication records

### Adversaries

**Who might detect you:**
1. **Target organizations**: May monitor their infrastructure
2. **ISPs**: Can see your traffic
3. **Surveillance systems**: IDS/IPS, WAFs, honeypots
4. **Law enforcement**: If operating without authorization
5. **Other analysts**: Competing intelligence teams

## Pre-Operation Checklist

### Before Starting Any Investigation

```
[ ] Legal authorization obtained
[ ] Scope clearly defined
[ ] Anonymization configured (Tor/VPN)
[ ] DNS leak prevention verified
[ ] Browser fingerprint randomized
[ ] Fresh operational identity created
[ ] Secure communication established
[ ] Encrypted storage prepared
[ ] Audit logging enabled
[ ] Emergency procedures reviewed
```

## Anonymization Layers

### Layer 1: Network Anonymization

**Use Tor for maximum anonymity:**

```python
from privacy.tor_proxy import TorSession

# All traffic through Tor
session = TorSession()
response = session.get('https://target.com')

# Renew circuit periodically
session.renew_circuit()
```

**Best practices:**
- Use Tor Browser for web browsing
- Don't mix Tor and clearnet traffic
- Renew circuits between targets
- Never login to personal accounts over Tor

### Layer 2: VPN + Tor (Double Protection)

**Chain VPN → Tor for defense in depth:**

```bash
# 1. Connect to VPN
sudo openvpn --config vpn.ovpn

# 2. Start Tor
tor

# 3. Configure tools to use Tor
export http_proxy=socks5://127.0.0.1:9050
export https_proxy=socks5://127.0.0.1:9050
```

**Rationale:**
- VPN hides Tor usage from ISP
- Tor hides destination from VPN provider
- If one fails, you have backup protection

### Layer 3: Proxy Rotation

**Rotate proxies to avoid correlation:**

```python
from privacy.proxy_rotation import ProxyRotator, ProxySession

rotator = ProxyRotator()
rotator.load_from_file('proxies.txt')
rotator.health_check()

session = ProxySession(rotator, strategy='random')
response = session.get('https://target.com')
```

**Guidelines:**
- Use different proxies for different targets
- Test proxies before operations
- Monitor for dead proxies
- Don't reuse burnt proxies

## Request Obfuscation

### Avoid Browser Fingerprinting

**Randomize your fingerprint:**

```python
from privacy.request_obfuscation import ObfuscatedSession

session = ObfuscatedSession(
    min_delay=2.0,  # Minimum 2 seconds between requests
    max_delay=5.0,   # Maximum 5 seconds
    requests_per_minute=10  # Rate limit
)

# Each request has different fingerprint
response = session.get('https://target.com')

# Rotate identity periodically
session.rotate_identity()
```

**Key elements:**
- Random User-Agents
- Random HTTP headers
- Random timing patterns
- Realistic browser behavior

### Rate Limiting

**Never hammer servers:**

```python
import time

def scan_targets(targets):
    for target in targets:
        process_target(target)
        
        # Random delay between requests
        delay = random.uniform(2, 5)
        time.sleep(delay)
```

**Rules:**
- Maximum 10-20 requests per minute
- Random delays between requests
- Respect robots.txt
- Monitor for blocking/throttling

## Data Security

### Credential Management

**Never store credentials in plaintext:**

```python
from privacy.secure_credentials import SecureCredentialStore

store = SecureCredentialStore()
store.unlock("your_master_password")

# Store API keys
store.set("SHODAN_API_KEY", "your_key_here")
store.save()

# Retrieve when needed
api_key = store.get("SHODAN_API_KEY")
```

**Best practices:**
- Use unique API keys per operation
- Rotate keys regularly
- Revoke keys after use
- Monitor key usage logs

### Data Encryption

**Encrypt all intelligence data:**

```python
from cryptography.fernet import Fernet

# Generate key
key = Fernet.generate_key()
cipher = Fernet(key)

# Encrypt data
encrypted = cipher.encrypt(intelligence_data.encode())

# Save encrypted
with open('intel.enc', 'wb') as f:
    f.write(encrypted)
```

**Storage requirements:**
- Full disk encryption (LUKS, FileVault, BitLocker)
- Encrypted containers for sensitive data
- Secure backups (encrypted)
- Secure deletion when no longer needed

### PII Handling

**Sanitize data before sharing:**

```python
from privacy.data_sanitization import DataSanitizer

# Remove PII from results
sanitized = DataSanitizer.redact(results)

# Pseudonymize if needed
pseudonym = DataSanitizer.hash_pii(email_address)
```

**Guidelines:**
- Collect minimum necessary PII
- Pseudonymize when possible
- Anonymize for sharing
- Delete when investigation complete

## Operational Compartmentalization

### Separate Identities

**Never mix operational and personal:**

| Personal | Operational |
|----------|-------------|
| Real name | Pseudonym/handle |
| Personal email | Dedicated email |
| Regular browser | Tor Browser |
| Personal devices | Dedicated devices |
| Social media | No social media |

### Dedicated Infrastructure

**Use separate systems:**
- **Dedicated laptop**: For OSINT operations only
- **Burner phones**: For SMS verification
- **Virtual machines**: Isolated environments
- **Live OS**: Tails, Kali Linux (no persistence)

### Clean Digital Footprint

**Don't leave traces:**

```bash
# Clear browser data
# Use private/incognito mode
# Disable browser history

# Clear bash history
history -c
history -w

# Clear system logs (with permission)
sudo journalctl --vacuum-time=1s

# Secure delete temporary files
python standalone/secure_delete.py /tmp/osint_* -r
```

## Communication Security

### Secure Channels

**Use encrypted communication:**

| Channel | Security | Use Case |
|---------|----------|----------|
| Signal | End-to-end encrypted | Team communication |
| PGP Email | Encrypted email | Formal reports |
| XMPP+OTR | Encrypted chat | Real-time coordination |
| Tor Hidden Services | Anonymous | Covert operations |

### Metadata Awareness

**Metadata can reveal your identity:**

```bash
# Remove EXIF from images
python standalone/metadata_scrubber.py photo.jpg -o clean.jpg

# Remove PDF metadata
python standalone/metadata_scrubber.py report.pdf -o clean.pdf
```

**Metadata to remove:**
- EXIF (GPS, camera, timestamps)
- PDF (author, software, creation date)
- Office docs (author, company, edit history)

## Leak Prevention

### DNS Leaks

**Check for DNS leaks:**

```bash
# Run DNS leak test
python standalone/dns_leak_checker.py

# Output shows if DNS is leaking to ISP
```

**Mitigation:**
- Configure VPN to use VPN DNS
- Set manual DNS (1.1.1.1, 8.8.8.8)
- Use DNS leak protection in VPN client

### WebRTC Leaks

**WebRTC can leak real IP:**

**Mitigations:**
1. Disable WebRTC in browser
2. Use browser extension (uBlock Origin)
3. Test at: https://browserleaks.com/webrtc

### IPv6 Leaks

**IPv6 can bypass VPN:**

```bash
# Disable IPv6 (Linux)
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1
sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1

# Make permanent
echo "net.ipv6.conf.all.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
```

## Logging and Audit

### Operational Logging

**Log operations securely:**

```python
from privacy.secure_logging import AuditLogger

logger = AuditLogger(encrypt=True)

# Log operations
logger.log_operation('domain_lookup', 'target.com')
logger.log_success('port_scan', '192.168.1.1', 'Found 3 ports')

# Export log
logger.export_session_log('operation.log')
```

**What to log:**
- Operation start/end times
- Targets investigated
- Tools used
- Results (sanitized)
- Errors and anomalies

**What NOT to log:**
- Full PII (log pseudonyms)
- Plaintext credentials
- Unnecessary metadata

### Audit Trail

**Maintain evidence chain:**
1. Document authorization
2. Log all operations
3. Timestamp all activities
4. Preserve original data
5. Hash evidence files

## Detection Avoidance

### IDS/IPS Evasion

**Avoid triggering alerts:**

- **Slow scans**: Use delays between requests
- **Fragmentation**: Split large requests
- **Legitimate patterns**: Mimic normal traffic
- **Avoid signatures**: Don't use default tool strings

### WAF Bypass

**Web Application Firewalls look for:**
- SQL injection patterns
- XSS attempts
- Malicious User-Agents
- Known scanner signatures
- Abnormal request rates

**Evasion:**
- Use realistic User-Agents
- Rate limit requests
- Avoid suspicious patterns
- Rotate IP addresses

### Honeypot Detection

**Indicators of honeypots:**
- Too-perfect systems
- Unusual network behavior
- Delayed responses
- Fake services

**Best practice:**
- Passive reconnaissance first
- Validate targets before active probing
- Watch for anomalies
- Back off if suspicious

## Incident Response

### If Detected

**Immediate actions:**

1. **Stop all operations immediately**
2. **Disconnect from network**
3. **Assess what was exposed**
4. **Notify team/client**
5. **Document incident**
6. **Analyze what went wrong**

### If Compromised

**If your identity is exposed:**

1. **Burn the identity**: Abandon compromised accounts
2. **Rotate credentials**: Change all API keys
3. **New infrastructure**: Fresh VPNs, proxies
4. **Legal review**: Consult attorney if needed
5. **Post-incident analysis**: Learn from mistakes

## Legal Compliance

### Always Obtain Authorization

**Required documentation:**
- Written authorization letter
- Scope of work agreement
- Data handling procedures
- Legal basis documented

### Know the Laws

**Critical regulations:**
- **CFAA** (US): Computer Fraud and Abuse Act
- **GDPR** (EU): Data protection
- **ECPA** (US): Electronic communications
- **Export controls**: Tool restrictions

### Emergency Contacts

**Keep ready:**
- Legal counsel contact
- Client escalation path
- Incident response team
- Law enforcement liaison (if authorized)

## Tools Summary

### Anonymization
```bash
# Tor integration
python -c "from privacy.tor_proxy import TorSession; print('Tor ready')"

# Proxy rotation
python -c "from privacy.proxy_rotation import ProxyRotator; print('Proxies ready')"

# Request obfuscation
python -c "from privacy.request_obfuscation import ObfuscatedSession; print('Obfuscation ready')"
```

### Security
```bash
# Secure credentials
python -c "from privacy.secure_credentials import SecureCredentialStore; print('Creds ready')"

# Data sanitization
python -c "from privacy.data_sanitization import DataSanitizer; print('Sanitizer ready')"

# DNS leak check
python standalone/dns_leak_checker.py

# Metadata scrubber
python standalone/metadata_scrubber.py file.jpg -o clean.jpg

# Secure delete
python standalone/secure_delete.py sensitive_file.txt

# MAC randomization (Linux, requires root)
sudo bash standalone/mac_randomizer.sh wlan0
```

## Training and Practice

### OPSEC Drills

**Regular practice:**
1. Simulated investigations
2. Leak testing
3. Incident response drills
4. Tool verification
5. Process reviews

### Continuous Improvement

**After each operation:**
- Document lessons learned
- Update procedures
- Test new techniques
- Review security posture
- Train team members

## Final Checklist

### Before Every Operation

```
[ ] Authorization verified
[ ] Anonymization tested
[ ] Leaks checked (DNS, WebRTC, IPv6)
[ ] Credentials secured
[ ] Logging enabled
[ ] Emergency plan ready
[ ] Team informed
[ ] Legal requirements met
```

### After Every Operation

```
[ ] All data encrypted
[ ] Logs sanitized
[ ] PII minimized
[ ] Credentials rotated
[ ] Temporary files deleted
[ ] Report generated
[ ] Evidence preserved
[ ] Post-op review scheduled
```

---

**Remember: Perfect OPSEC doesn't exist. Minimize risk through layered defenses and constant vigilance.**

**Copyright © 2025-2026 Lackadaisical Security. All rights reserved.**
