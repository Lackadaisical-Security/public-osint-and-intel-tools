import requests
from bs4 import BeautifulSoup
from typing import Dict, List, Any
from urllib.parse import urljoin, urlparse
import re
from config import Config

class WebScraper:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': Config.USER_AGENT})
        
    def scrape_intel(self, url: str) -> Dict[str, Any]:
        """Scrape intelligence from a website"""
        results = {
            'url': url,
            'emails': [],
            'phone_numbers': [],
            'social_links': [],
            'technologies': [],
            'meta_info': {},
            'links': {
                'internal': [],
                'external': []
            }
        }
        
        try:
            response = self.session.get(url, timeout=Config.REQUEST_TIMEOUT)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract emails
            results['emails'] = self._extract_emails(response.text)
            
            # Extract phone numbers
            results['phone_numbers'] = self._extract_phones(response.text)
            
            # Extract social media links
            results['social_links'] = self._extract_social_links(soup, url)
            
            # Extract meta information
            results['meta_info'] = self._extract_meta_info(soup)
            
            # Extract and categorize links
            results['links'] = self._extract_links(soup, url)
            
            # Detect technologies
            results['technologies'] = self._detect_technologies(response)
            
        except Exception as e:
            results['error'] = str(e)
            
        return results
    
    def _extract_emails(self, text: str) -> List[str]:
        """Extract email addresses from text"""
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = list(set(re.findall(email_pattern, text)))
        return [email for email in emails if not email.endswith('.png') and not email.endswith('.jpg')]
    
    def _extract_phones(self, text: str) -> List[str]:
        """Extract phone numbers from text"""
        phone_patterns = [
            r'\+?1?\s*\(?[0-9]{3}\)?[\s.-]?[0-9]{3}[\s.-]?[0-9]{4}',
            r'\+[0-9]{1,3}\s?[0-9]{1,14}'
        ]
        phones = []
        for pattern in phone_patterns:
            phones.extend(re.findall(pattern, text))
        return list(set(phones))
    
    def _extract_social_links(self, soup: BeautifulSoup, base_url: str) -> List[Dict[str, str]]:
        """Extract social media links"""
        social_platforms = {
            'facebook.com': 'Facebook',
            'twitter.com': 'Twitter',
            'linkedin.com': 'LinkedIn',
            'instagram.com': 'Instagram',
            'youtube.com': 'YouTube',
            'github.com': 'GitHub'
        }
        
        social_links = []
        for link in soup.find_all('a', href=True):
            href = link['href']
            for platform_url, platform_name in social_platforms.items():
                if platform_url in href:
                    social_links.append({
                        'platform': platform_name,
                        'url': urljoin(base_url, href)
                    })
                    
        return social_links
    
    def _extract_meta_info(self, soup: BeautifulSoup) -> Dict[str, str]:
        """Extract meta information"""
        meta_info = {}
        
        # Title
        if soup.title:
            meta_info['title'] = soup.title.string
            
        # Meta tags
        for meta in soup.find_all('meta'):
            if meta.get('name'):
                meta_info[meta['name']] = meta.get('content', '')
            elif meta.get('property'):
                meta_info[meta['property']] = meta.get('content', '')
                
        return meta_info
    
    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> Dict[str, List[str]]:
        """Extract and categorize links"""
        internal_links = []
        external_links = []
        base_domain = urlparse(base_url).netloc
        
        for link in soup.find_all('a', href=True):
            href = urljoin(base_url, link['href'])
            if urlparse(href).netloc == base_domain:
                internal_links.append(href)
            else:
                external_links.append(href)
                
        return {
            'internal': list(set(internal_links))[:20],  # Limit to 20
            'external': list(set(external_links))[:20]
        }
    
    def _detect_technologies(self, response: requests.Response) -> List[str]:
        """Detect technologies used by the website"""
        technologies = []
        
        # Check headers
        if 'X-Powered-By' in response.headers:
            technologies.append(response.headers['X-Powered-By'])
        if 'Server' in response.headers:
            technologies.append(response.headers['Server'])
            
        # Check for common frameworks in HTML
        html_checks = {
            'WordPress': ['wp-content', 'wp-includes'],
            'React': ['react', 'reactdom'],
            'Angular': ['ng-app', 'angular'],
            'Vue.js': ['vue.js', 'vue.min.js'],
            'jQuery': ['jquery.min.js', 'jquery.js']
        }
        
        for tech, patterns in html_checks.items():
            for pattern in patterns:
                if pattern in response.text.lower():
                    technologies.append(tech)
                    break
                    
        return list(set(technologies))
