import re
import dns.resolver
import requests
from typing import Dict, Any, List
import validators

class EmailIntel:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        
    def gather_intel(self, email: str) -> Dict[str, Any]:
        """Gather intelligence about an email address"""
        if not self._validate_email(email):
            return {'error': 'Invalid email format'}
            
        username, domain = email.split('@')
        
        results = {
            'email': email,
            'username': username,
            'domain': domain,
            'valid_format': True,
            'mx_records': [],
            'disposable': False,
            'breach_check': None,
            'social_profiles': []
        }
        
        # Check MX records
        results['mx_records'] = self._check_mx_records(domain)
        
        # Check if disposable email
        results['disposable'] = self._check_disposable(domain)
        
        # Search for social profiles
        results['social_profiles'] = self._search_social_profiles(username)
        
        return results
    
    def _validate_email(self, email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def _check_mx_records(self, domain: str) -> List[str]:
        """Check MX records for domain"""
        try:
            mx_records = []
            answers = self.resolver.resolve(domain, 'MX')
            for rdata in answers:
                mx_records.append(f"{rdata.preference} {rdata.exchange}")
            return mx_records
        except:
            return []
    
    def _check_disposable(self, domain: str) -> bool:
        """Check if email domain is disposable"""
        disposable_domains = [
            'tempmail.com', '10minutemail.com', 'guerrillamail.com',
            'mailinator.com', 'throwaway.email', 'yopmail.com'
        ]
        return domain.lower() in disposable_domains
    
    def _search_social_profiles(self, username: str) -> List[Dict[str, str]]:
        """Search for potential social media profiles"""
        platforms = {
            'GitHub': f'https://github.com/{username}',
            'Twitter': f'https://twitter.com/{username}',
            'Instagram': f'https://instagram.com/{username}',
            'LinkedIn': f'https://linkedin.com/in/{username}',
            'Reddit': f'https://reddit.com/user/{username}'
        }
        
        found_profiles = []
        for platform, url in platforms.items():
            found_profiles.append({
                'platform': platform,
                'url': url,
                'status': 'Check manually'
            })
            
        return found_profiles
