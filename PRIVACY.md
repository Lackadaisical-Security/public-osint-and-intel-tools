# Privacy Policy & Data Handling Guidelines

## Philosophy

**Intelligence gathering without privacy is surveillance.** This project is designed for legitimate OSINT operations while respecting privacy rights and data protection laws.

## Data We Collect

### Short Answer: **Nothing**

These are local tools. We don't operate servers, we don't collect telemetry, we don't phone home.

**Zero data collection. Zero tracking. Zero telemetry.**

### What Runs Locally

All tools execute entirely on your system:
- No analytics
- No crash reporting
- No usage statistics
- No network callbacks to us
- No embedded trackers

**Your operations are your business.**

## Data You Collect

### Your Responsibility

When you use these tools to gather intelligence, **you** are the data controller:
- You determine what data to collect
- You determine how to store it
- You determine how to use it
- You are responsible for legal compliance

### Legal Obligations

**You must comply with:**
- **GDPR** (EU): General Data Protection Regulation
- **CCPA** (California): California Consumer Privacy Act
- **PIPEDA** (Canada): Personal Information Protection and Electronic Documents Act
- **Privacy Act** (Australia): Australian Privacy Principles
- **Other jurisdictions**: Local data protection laws

**Key principles:**
1. **Lawfulness**: Have legal basis for data processing
2. **Purpose Limitation**: Only collect data for specific purposes
3. **Data Minimization**: Collect only necessary data
4. **Accuracy**: Ensure data is accurate and up-to-date
5. **Storage Limitation**: Don't keep data longer than needed
6. **Security**: Protect data from unauthorized access
7. **Accountability**: Be able to demonstrate compliance

## Privacy-Preserving Features

### Encrypted Credential Storage

**Never store API keys in plaintext:**

```python
from privacy.secure_credentials import SecureCredentialStore

# Encrypted storage
store = SecureCredentialStore()
store.unlock("your_master_password")
store.set("SHODAN_API_KEY", "your_api_key")
store.save()

# Credentials encrypted at rest
# Password-based key derivation (PBKDF2)
# File permissions restricted to owner
```

### Anonymous Intelligence Gathering

**Use Tor for anonymity:**

```python
from privacy.tor_proxy import TorSession

# All requests through Tor network
session = TorSession()
response = session.get('https://target.com')

# Your IP is hidden
# Traffic is encrypted
# Exit node location is randomized
```

**Use proxy rotation:**

```python
from privacy.proxy_rotation import ProxyRotator, ProxySession

# Rotate through multiple proxies
rotator = ProxyRotator()
rotator.add_proxy('socks5', 'proxy1.com', 1080)
rotator.add_proxy('socks5', 'proxy2.com', 1080)

session = ProxySession(rotator)
response = session.get('https://target.com')
# Each request uses different proxy
```

### Request Obfuscation

**Avoid fingerprinting:**

```python
from privacy.request_obfuscation import ObfuscatedSession

# Randomized browser fingerprints
session = ObfuscatedSession()
response = session.get('https://target.com')

# Random User-Agents
# Random HTTP headers
# Random timing patterns
# Harder to correlate requests
```

### Data Sanitization

**Remove PII before sharing:**

```python
import re

def sanitize_email(text):
    """Replace emails with [EMAIL]"""
    return re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 
                  '[EMAIL]', text)

def sanitize_phone(text):
    """Replace phone numbers with [PHONE]"""
    return re.sub(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '[PHONE]', text)

def sanitize_ip(text):
    """Replace IPs with [IP]"""
    return re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[IP]', text)

# Sanitize results before sharing
sanitized = sanitize_email(sanitize_phone(sanitize_ip(results)))
```

### Metadata Removal

**Strip metadata from files:**

```bash
# Remove EXIF from images
python standalone/metadata_scrubber.py photo.jpg -o clean_photo.jpg

# Remove metadata from PDFs
python standalone/metadata_scrubber.py document.pdf -o clean_doc.pdf

# Batch process directory
python standalone/metadata_scrubber.py ./files/ -o ./clean_files/ -r
```

### DNS Leak Prevention

**Check for DNS leaks:**

```bash
# Verify DNS isn't leaking your location
python standalone/dns_leak_checker.py

# Output shows if DNS queries are going through VPN/Tor
# or leaking to your ISP
```

## Data Retention Guidelines

### Minimize Storage

**Collect only what you need:**
- Don't save everything "just in case"
- Delete data when investigation complete
- Use temporary storage for transient data
- Encrypt storage media

### Secure Storage

**Protect stored intelligence:**

```python
# Encrypt files at rest
from cryptography.fernet import Fernet

# Generate key
key = Fernet.generate_key()
cipher = Fernet(key)

# Encrypt data
encrypted_data = cipher.encrypt(intelligence_data.encode())

# Save encrypted
with open('intel.enc', 'wb') as f:
    f.write(encrypted_data)

# Decrypt when needed
with open('intel.enc', 'rb') as f:
    decrypted = cipher.decrypt(f.read()).decode()
```

**File system encryption:**
- **Linux**: LUKS, eCryptfs
- **macOS**: FileVault
- **Windows**: BitLocker
- **Cross-platform**: VeraCrypt

### Secure Deletion

**Truly delete sensitive data:**

```bash
# Secure delete (Linux/macOS)
shred -vfz -n 10 sensitive_file.txt

# Secure delete (cross-platform with Python)
python standalone/secure_delete.py sensitive_file.txt
```

## PII Handling Best Practices

### What is PII?

**Personally Identifiable Information includes:**
- Names
- Email addresses
- Phone numbers
- Physical addresses
- IP addresses
- Social Security Numbers
- Passport numbers
- Biometric data
- Location data
- Financial information

### Minimize PII Collection

**Ask yourself:**
1. Do I really need this data?
2. Can I achieve my goal without PII?
3. Can I pseudonymize or anonymize?
4. How long do I need to keep it?

### Pseudonymization

**Replace identifiers with tokens:**

```python
import hashlib
import hmac

def pseudonymize(pii_value, secret_key):
    """Convert PII to non-reversible token"""
    return hmac.new(
        secret_key.encode(),
        pii_value.encode(),
        hashlib.sha256
    ).hexdigest()

# Example
email = "john.doe@example.com"
secret = "your_secret_key_here"
token = pseudonymize(email, secret)
# token: "a3f5e8d7c9b2..."

# Use token in analysis, discard original email
```

### Anonymization

**Remove all identifying information:**

```python
def anonymize_record(record):
    """Remove all PII from intelligence record"""
    anonymized = {}
    
    # Keep non-PII fields
    if 'domain' in record:
        anonymized['domain'] = record['domain']
    if 'ip_geolocation' in record:
        # Keep country, remove exact location
        geo = record['ip_geolocation']
        anonymized['country'] = geo.get('country')
        # Don't include city, lat/lon
    
    # Remove PII fields
    # Don't copy: name, email, phone, address, etc.
    
    return anonymized
```

## Consent & Authorization

### Required Authorization

**Before gathering intelligence, obtain:**

1. **Written authorization** from:
   - Organization being assessed (penetration testing)
   - Legal authority (law enforcement with warrant)
   - Individual (personal privacy audit)

2. **Scope definition**:
   - What systems/domains are in scope
   - What techniques are permitted
   - Time window for assessment
   - Data handling requirements

3. **Legal review**:
   - Ensure compliance with local laws
   - Verify authorization is sufficient
   - Document legal basis

### Public vs. Private Data

**Public data doesn't mean no restrictions:**

**Public data (generally OK):**
- Information on public websites
- Social media profiles set to public
- Public DNS records
- Public WHOIS information
- Public company filings

**Restricted (even if technically accessible):**
- Data behind authentication
- Data obtained through exploitation
- Data scraped in violation of ToS
- Data aggregated to de-anonymize individuals
- Data from breaches or leaks

**Private data (requires authorization):**
- Email content
- Private messages
- Internal systems
- Personal computers
- Non-public databases

## Third-Party Services

### API Data Handling

**When using APIs (Shodan, VirusTotal, etc.):**

**Understand their privacy policies:**
- What data do they collect?
- How long do they retain it?
- Who has access to it?
- Can they use it for other purposes?

**Best practices:**
- Use dedicated API keys per operation
- Rotate keys regularly
- Don't send PII in API queries if avoidable
- Read and comply with Terms of Service
- Consider self-hosting alternatives

### Service Providers

**This project integrates with:**

| Service | Purpose | Data Shared | Privacy Policy |
|---------|---------|-------------|----------------|
| Shodan | IP intelligence | IP addresses | [Link](https://account.shodan.io/privacy) |
| VirusTotal | Malware analysis | File hashes, URLs | [Link](https://support.virustotal.com/hc/en-us/articles/115002168385-Privacy-Policy) |
| HaveIBeenPwned | Breach checking | Email addresses | [Link](https://haveibeenpwned.com/Privacy) |

**You are responsible for:**
- Reviewing their privacy policies
- Complying with their terms
- Not sending unauthorized data
- Understanding data retention

## Data Subject Rights

### If You Collect Data About People

**Data subjects have rights:**

**GDPR Rights:**
- **Right to access**: Provide copy of their data
- **Right to rectification**: Correct inaccurate data
- **Right to erasure**: Delete their data ("right to be forgotten")
- **Right to restrict processing**: Limit how you use data
- **Right to data portability**: Provide data in machine-readable format
- **Right to object**: Object to certain processing

**How to comply:**
1. Maintain records of data collected
2. Implement data access procedures
3. Have deletion procedures
4. Respond to requests within 30 days (GDPR)
5. Verify identity before disclosing data

## Incident Response

### Data Breach

**If intelligence data is compromised:**

1. **Contain**: Isolate affected systems
2. **Assess**: Determine what data was exposed
3. **Notify**: 
   - Affected individuals (if PII exposed)
   - Authorities (if required by law)
   - Client/organization (if applicable)
4. **Remediate**: Fix vulnerability
5. **Document**: Post-incident report

**Notification requirements:**
- **GDPR**: 72 hours to notify authorities, prompt notification to individuals
- **CCPA**: Without unreasonable delay
- **State laws**: Varies by jurisdiction

## Privacy By Design

### Build Privacy In

**When developing new tools:**

1. **Default to privacy**: Opt-in for data collection, not opt-out
2. **Minimize data**: Only collect what's necessary
3. **Encrypt everything**: At rest and in transit
4. **No persistent identifiers**: Don't track users
5. **Anonymous by default**: Don't require authentication unless needed
6. **Transparent**: Document what data is processed
7. **User control**: Let users delete their data

## Children's Privacy

**Do not:**
- Gather intelligence about minors (under 18)
- Process data of children without parental consent
- Target minors with OSINT operations

**Exceptions:**
- Law enforcement with proper authorization
- Child protection investigations
- Academic research with IRB approval

## Contact for Privacy Concerns

**Privacy questions or concerns:**
- **Email**: lackadaisicalresearch@pm.me
- **Subject**: [PRIVACY] Your concern

**Data breach notifications:**
- **Email**: lackadaisicalresearch@pm.me
- **Subject**: [BREACH] Description

---

**Remember: With great intelligence capability comes great responsibility. Respect privacy.**

**Copyright © 2025-2026 Lackadaisical Security. All rights reserved.**
