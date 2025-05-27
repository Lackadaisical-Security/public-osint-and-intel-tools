#!/usr/bin/env python3
"""
Domain Reconnaissance - Standalone Script
Lackadaisical Security - https://lackadaisical-security.com/
No external dependencies required - uses only standard library
"""

import socket
import ssl
import subprocess
import sys
import json
import time
import re
from urllib.request import urlopen
from urllib.error import URLError
import base64
from datetime import datetime

class DomainRecon:
    def __init__(self, domain):
        self.domain = domain.lower().strip()
        self.results = {
            'domain': self.domain,
            'timestamp': datetime.now().isoformat(),
            'dns_records': {},
            'ssl_info': {},
            'http_headers': {},
            'whois_info': {},
            'subdomains': [],
            'technologies': []
        }
    
    def get_dns_records(self):
        """Get DNS records using socket library"""
        print(f"[*] Fetching DNS records for {self.domain}...")
        
        # A records
        try:
            ips = socket.gethostbyname_ex(self.domain)[2]
            self.results['dns_records']['A'] = ips
            print(f"[+] A records: {', '.join(ips)}")
        except:
            self.results['dns_records']['A'] = []
            print("[-] No A records found")
        
        # Try to get MX records using nslookup (cross-platform)
        try:
            if sys.platform == "win32":
                output = subprocess.check_output(f"nslookup -type=MX {self.domain}", shell=True, text=True)
            else:
                output = subprocess.check_output(f"nslookup -query=MX {self.domain}", shell=True, text=True)
            
            mx_records = []
            for line in output.split('\n'):
                if 'mail exchanger' in line or 'MX preference' in line:
                    mx_records.append(line.strip())
            self.results['dns_records']['MX'] = mx_records
            if mx_records:
                print(f"[+] Found {len(mx_records)} MX records")
        except:
            self.results['dns_records']['MX'] = []
    
    def check_ssl_cert(self):
        """Check SSL certificate information"""
        print(f"[*] Checking SSL certificate...")
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    self.results['ssl_info'] = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'alt_names': [x[1] for x in cert.get('subjectAltName', [])]
                    }
                    print(f"[+] SSL cert valid until: {cert['notAfter']}")
                    
                    # Extract subdomains from alt names
                    for alt_name in self.results['ssl_info']['alt_names']:
                        if '*' not in alt_name and alt_name.endswith(self.domain):
                            subdomain = alt_name.replace(f".{self.domain}", '')
                            if subdomain and subdomain not in self.results['subdomains']:
                                self.results['subdomains'].append(subdomain)
                                print(f"[+] Found subdomain from cert: {alt_name}")
        except Exception as e:
            self.results['ssl_info'] = {'error': str(e)}
            print(f"[-] SSL check failed: {e}")
    
    def get_http_headers(self):
        """Get HTTP headers"""
        print(f"[*] Fetching HTTP headers...")
        
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{self.domain}"
                response = urlopen(url, timeout=10)
                headers = dict(response.headers)
                
                self.results['http_headers'][protocol] = headers
                print(f"[+] Got {len(headers)} headers from {protocol}")
                
                # Detect technologies from headers
                if 'Server' in headers:
                    self.results['technologies'].append(f"Server: {headers['Server']}")
                if 'X-Powered-By' in headers:
                    self.results['technologies'].append(f"Powered by: {headers['X-Powered-By']}")
                
                break
            except:
                continue
    
    def basic_port_scan(self):
        """Scan common ports"""
        print(f"[*] Scanning common ports...")
        
        common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
        }
        
        open_ports = []
        for port, service in common_ports.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.domain, port))
            sock.close()
            
            if result == 0:
                open_ports.append({'port': port, 'service': service})
                print(f"[+] Port {port} ({service}) is open")
        
        self.results['open_ports'] = open_ports
    
    def enumerate_subdomains(self):
        """Basic subdomain enumeration"""
        print(f"[*] Enumerating subdomains...")
        
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'blog', 'dev',
            'staging', 'test', 'portal', 'secure', 'vpn', 'remote'
        ]
        
        found = []
        for sub in common_subdomains:
            try:
                full_domain = f"{sub}.{self.domain}"
                socket.gethostbyname(full_domain)
                found.append(sub)
                print(f"[+] Found: {full_domain}")
            except:
                pass
        
        self.results['subdomains'].extend([s for s in found if s not in self.results['subdomains']])
    
    def run_recon(self):
        """Run all reconnaissance tasks"""
        print(f"\n{'='*60}")
        print(f"Domain Reconnaissance - Lackadaisical Security")
        print(f"Target: {self.domain}")
        print(f"{'='*60}\n")
        
        self.get_dns_records()
        self.check_ssl_cert()
        self.get_http_headers()
        self.basic_port_scan()
        self.enumerate_subdomains()
        
        return self.results

def print_report(results):
    """Print formatted report"""
    print(f"\n{'='*60}")
    print("RECONNAISSANCE REPORT")
    print(f"{'='*60}")
    
    print(f"\nDomain: {results['domain']}")
    print(f"Scan Time: {results['timestamp']}")
    
    print("\n[DNS Records]")
    for record_type, records in results['dns_records'].items():
        if records:
            print(f"  {record_type}: {records}")
    
    print("\n[SSL Certificate]")
    if 'error' not in results['ssl_info']:
        ssl_info = results['ssl_info']
        if ssl_info:
            print(f"  Issuer: {ssl_info.get('issuer', {}).get('organizationName', 'N/A')}")
            print(f"  Valid until: {ssl_info.get('not_after', 'N/A')}")
            print(f"  Alt names: {len(ssl_info.get('alt_names', []))}")
    
    print("\n[Open Ports]")
    for port_info in results.get('open_ports', []):
        print(f"  {port_info['port']}/{port_info['service']}")
    
    print("\n[Subdomains Found]")
    for subdomain in results.get('subdomains', []):
        print(f"  {subdomain}.{results['domain']}")
    
    print("\n[Technologies Detected]")
    for tech in results.get('technologies', []):
        print(f"  {tech}")
    
    print(f"\n{'='*60}")
    print("Report generated by Lackadaisical Security")
    print("https://lackadaisical-security.com/")
    print(f"{'='*60}\n")

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <domain>")
        print(f"Example: {sys.argv[0]} example.com")
        sys.exit(1)
    
    domain = sys.argv[1]
    recon = DomainRecon(domain)
    results = recon.run_recon()
    
    print_report(results)
    
    # Save results
    filename = f"{domain.replace('.', '_')}_recon_{int(time.time())}.json"
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Results saved to: {filename}")

if __name__ == "__main__":
    main()
