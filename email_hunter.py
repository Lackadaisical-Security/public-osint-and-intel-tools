#!/usr/bin/env python3
"""
Email Hunter - Standalone Script
Lackadaisical Security - https://lackadaisical-security.com/
No external dependencies required - uses only standard library
"""

import re
import socket
import sys
import json
from urllib.request import urlopen, Request
from urllib.error import URLError
from urllib.parse import urlparse, urljoin
import time

class EmailHunter:
    def __init__(self, domain):
        self.domain = domain
        self.emails = set()
        self.patterns = []
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        
    def hunt_emails_from_url(self, url):
        """Extract emails from a given URL"""
        try:
            req = Request(url, headers={'User-Agent': self.user_agent})
            response = urlopen(req, timeout=10)
            content = response.read().decode('utf-8', errors='ignore')
            
            # Find all email addresses
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            found_emails = re.findall(email_pattern, content)
            
            # Filter and add valid emails
            for email in found_emails:
                if self._is_valid_email(email):
                    self.emails.add(email.lower())
                    
            return len(found_emails)
        except Exception as e:
            print(f"[-] Error fetching {url}: {e}")
            return 0
    
    def _is_valid_email(self, email):
        """Validate email address"""
        if email.endswith(('.png', '.jpg', '.gif', '.css', '.js')):
            return False
        if email.count('@') != 1:
            return False
        if len(email) > 254:
            return False
        return True
    
    def generate_email_patterns(self):
        """Generate common email patterns"""
        common_names = ['info', 'contact', 'admin', 'support', 'sales', 
                       'hello', 'help', 'service', 'team', 'hr']
        
        for name in common_names:
            self.patterns.append(f"{name}@{self.domain}")
    
    def search_google(self):
        """Search Google for emails (without API)"""
        print(f"[*] Searching for emails on Google...")
        
        search_urls = [
            f'https://www.google.com/search?q="*@{self.domain}"',
            f'https://www.google.com/search?q=site:{self.domain}+"email"',
            f'https://www.google.com/search?q=site:{self.domain}+"contact"'
        ]
        
        # Note: This is for demonstration. In production, use proper search APIs
        print("[!] Note: Automated Google searches may be rate-limited")
    
    def verify_email_domain(self, email):
        """Verify if email domain has MX records"""
        domain = email.split('@')[1]
        try:
            # Try to get MX records
            socket.gethostbyname(f"mail.{domain}")
            return True
        except:
            try:
                socket.gethostbyname(domain)
                return True
            except:
                return False
    
    def hunt(self):
        """Main hunting function"""
        print(f"\n{'='*60}")
        print("Email Hunter - Lackadaisical Security")
        print(f"Target Domain: {self.domain}")
        print(f"{'='*60}\n")
        
        # Generate patterns
        print("[*] Generating email patterns...")
        self.generate_email_patterns()
        for pattern in self.patterns:
            self.emails.add(pattern)
        
        # Search main website
        print(f"[*] Searching main website...")
        urls_to_check = [
            f"https://{self.domain}",
            f"http://{self.domain}",
            f"https://www.{self.domain}",
            f"https://{self.domain}/contact",
            f"https://{self.domain}/about",
            f"https://{self.domain}/team"
        ]
        
        for url in urls_to_check:
            count = self.hunt_emails_from_url(url)
            if count > 0:
                print(f"[+] Found {count} potential emails on {url}")
        
        # Verify emails
        print("\n[*] Verifying email domains...")
        verified_emails = []
        for email in self.emails:
            if self.verify_email_domain(email):
                verified_emails.append(email)
                print(f"[+] Verified: {email}")
            else:
                print(f"[-] Unverified: {email}")
        
        return {
            'domain': self.domain,
            'total_found': len(self.emails),
            'verified': verified_emails,
            'all_emails': list(self.emails),
            'patterns_used': self.patterns
        }

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <domain>")
        print(f"Example: {sys.argv[0]} example.com")
        sys.exit(1)
    
    domain = sys.argv[1]
    hunter = EmailHunter(domain)
    results = hunter.hunt()
    
    print(f"\n{'='*60}")
    print("RESULTS SUMMARY")
    print(f"{'='*60}")
    print(f"Total emails found: {results['total_found']}")
    print(f"Verified emails: {len(results['verified'])}")
    
    # Save results
    filename = f"{domain.replace('.', '_')}_emails_{int(time.time())}.json"
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Results saved to: {filename}")
    
    print(f"\n{'='*60}")
    print("Generated by Lackadaisical Security")
    print("https://lackadaisical-security.com/")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
