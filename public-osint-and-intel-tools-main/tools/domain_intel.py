import whois
import dns.resolver
import requests
from typing import Dict, List, Any
import socket
from urllib.parse import urlparse

class DomainIntel:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        
    def gather_intel(self, domain: str) -> Dict[str, Any]:
        """Gather comprehensive intelligence about a domain"""
        results = {
            'domain': domain,
            'whois': None,
            'dns_records': {},
            'subdomains': [],
            'ip_address': None,
            'ssl_info': None,
            'technologies': []
        }
        
        # Clean domain
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        
        # WHOIS lookup
        try:
            results['whois'] = self._get_whois(domain)
        except Exception as e:
            results['whois'] = f"Error: {str(e)}"
            
        # DNS records
        results['dns_records'] = self._get_dns_records(domain)
        
        # IP address
        try:
            results['ip_address'] = socket.gethostbyname(domain)
        except:
            results['ip_address'] = "Could not resolve"
            
        # Basic subdomain enumeration
        results['subdomains'] = self._enumerate_subdomains(domain)
        
        return results
    
    def _get_whois(self, domain: str) -> Dict[str, Any]:
        """Get WHOIS information"""
        try:
            w = whois.whois(domain)
            return {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers,
                'status': w.status,
                'emails': w.emails,
                'org': w.org
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _get_dns_records(self, domain: str) -> Dict[str, List[str]]:
        """Get DNS records"""
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = self.resolver.resolve(domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except:
                records[record_type] = []
                
        return records
    
    def _enumerate_subdomains(self, domain: str) -> List[str]:
        """Basic subdomain enumeration"""
        common_subdomains = ['www', 'mail', 'ftp', 'admin', 'api', 'blog', 
                           'dev', 'staging', 'test', 'portal', 'secure']
        found_subdomains = []
        
        for sub in common_subdomains:
            subdomain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                found_subdomains.append(subdomain)
            except:
                pass
                
        return found_subdomains
