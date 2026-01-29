import whois
import dns.resolver
import requests
import ssl
import socket
import concurrent.futures
from typing import Dict, List, Any, Set
from datetime import datetime
import re
import json
from urllib.parse import urlparse

class AdvancedDomainIntel:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
        self.session = requests.Session()
        
    def gather_intel(self, domain: str) -> Dict[str, Any]:
        """Gather comprehensive intelligence about a domain"""
        # Clean domain
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        
        results = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'whois': self._get_whois(domain),
            'dns_records': self._get_all_dns_records(domain),
            'subdomains': self._advanced_subdomain_enum(domain),
            'ssl_certificate': self._get_ssl_info(domain),
            'http_headers': self._get_http_headers(domain),
            'technologies': self._detect_technologies(domain),
            'email_addresses': self._find_email_addresses(domain),
            'related_domains': self._find_related_domains(domain),
            'historical_data': self._get_historical_data(domain),
            'security_headers': self._check_security_headers(domain),
            'ports': self._scan_common_ports(domain),
            'cdn_detection': self._detect_cdn(domain),
            'waf_detection': self._detect_waf(domain)
        }
        
        return results
    
    def _get_whois(self, domain: str) -> Dict[str, Any]:
        """Enhanced WHOIS information"""
        try:
            w = whois.whois(domain)
            whois_data = {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'last_updated': str(w.updated_date) if hasattr(w, 'updated_date') else None,
                'name_servers': w.name_servers,
                'status': w.status,
                'emails': w.emails,
                'dnssec': w.dnssec if hasattr(w, 'dnssec') else None,
                'org': w.org,
                'address': w.address if hasattr(w, 'address') else None,
                'city': w.city if hasattr(w, 'city') else None,
                'state': w.state if hasattr(w, 'state') else None,
                'country': w.country if hasattr(w, 'country') else None,
                'registrant_name': w.name if hasattr(w, 'name') else None
            }
            return whois_data
        except Exception as e:
            return {'error': str(e)}
    
    def _get_all_dns_records(self, domain: str) -> Dict[str, Any]:
        """Get comprehensive DNS records"""
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 
                       'PTR', 'SRV', 'CAA', 'DNSKEY', 'DMARC']
        
        for record_type in record_types:
            try:
                if record_type == 'DMARC':
                    answers = self.resolver.resolve(f'_dmarc.{domain}', 'TXT')
                else:
                    answers = self.resolver.resolve(domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except:
                records[record_type] = []
        
        # SPF record
        try:
            spf_records = []
            for txt in records.get('TXT', []):
                if 'v=spf1' in txt:
                    spf_records.append(txt)
            records['SPF'] = spf_records
        except:
            records['SPF'] = []
            
        return records
    
    def _advanced_subdomain_enum(self, domain: str) -> List[Dict[str, Any]]:
        """Advanced subdomain enumeration with threading"""
        subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'blog', 'dev', 'staging',
            'test', 'portal', 'secure', 'vpn', 'remote', 'webmail', 'ns1',
            'ns2', 'smtp', 'pop', 'imap', 'forum', 'news', 'media', 'status',
            'support', 'kb', 'help', 'cdn', 'cloud', 'app', 'mobile', 'gateway',
            'firewall', 'backup', 'monitor', 'metrics', 'grafana', 'prometheus',
            'jenkins', 'gitlab', 'github', 'bitbucket', 'jira', 'confluence',
            'wiki', 'docs', 'assets', 'images', 'img', 'static', 'download',
            'files', 'data', 'db', 'mysql', 'postgres', 'redis', 'elastic',
            'kibana', 'logstash', 'kafka', 'rabbitmq', 'api-v1', 'api-v2',
            'rest', 'graphql', 'grpc', 'websocket', 'ssh', 'sftp', 'ldap',
            'radius', 'ntp', 'snmp', 'syslog', 'graylog', 'splunk', 'nagios'
        ]
        
        found_subdomains = []
        
        def check_subdomain(sub):
            subdomain = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(subdomain)
                return {
                    'subdomain': subdomain,
                    'ip': ip,
                    'resolved': True
                }
            except:
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            results = executor.map(check_subdomain, subdomains)
            found_subdomains = [r for r in results if r is not None]
        
        # Try certificate transparency logs
        ct_subdomains = self._search_certificate_transparency(domain)
        for ct_sub in ct_subdomains:
            if not any(s['subdomain'] == ct_sub for s in found_subdomains):
                try:
                    ip = socket.gethostbyname(ct_sub)
                    found_subdomains.append({
                        'subdomain': ct_sub,
                        'ip': ip,
                        'resolved': True,
                        'source': 'certificate_transparency'
                    })
                except:
                    pass
        
        return found_subdomains
    
    def _search_certificate_transparency(self, domain: str) -> List[str]:
        """Search certificate transparency logs"""
        subdomains = set()
        try:
            # Using crt.sh
            response = self.session.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    if name and '*' not in name:
                        subdomains.add(name.lower())
        except:
            pass
        
        return list(subdomains)
    
    def _get_ssl_info(self, domain: str) -> Dict[str, Any]:
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'signature_algorithm': cert.get('signatureAlgorithm'),
                        'san': cert.get('subjectAltName', []),
                        'is_valid': datetime.now() < datetime.strptime(
                            cert['notAfter'], '%b %d %H:%M:%S %Y %Z'
                        )
                    }
        except Exception as e:
            return {'error': str(e)}
    
    def _get_http_headers(self, domain: str) -> Dict[str, Any]:
        """Get HTTP headers and response info"""
        headers_info = {}
        protocols = ['https', 'http']
        
        for protocol in protocols:
            try:
                response = self.session.get(
                    f"{protocol}://{domain}",
                    timeout=10,
                    allow_redirects=True
                )
                headers_info[protocol] = {
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'cookies': [
                        {
                            'name': c.name,
                            'value': c.value[:20] + '...' if len(c.value) > 20 else c.value,
                            'domain': c.domain,
                            'secure': c.secure,
                            'httponly': c.get_nonstandard_attr('HttpOnly')
                        }
                        for c in response.cookies
                    ],
                    'final_url': response.url,
                    'redirect_chain': [r.url for r in response.history]
                }
            except:
                headers_info[protocol] = {'error': 'Failed to connect'}
        
        return headers_info
    
    def _detect_technologies(self, domain: str) -> Dict[str, List[str]]:
        """Enhanced technology detection"""
        technologies = {
            'cms': [],
            'frameworks': [],
            'javascript_libraries': [],
            'web_servers': [],
            'programming_languages': [],
            'analytics': [],
            'cdn': [],
            'security': []
        }
        
        try:
            response = self.session.get(f"https://{domain}", timeout=10)
            headers = response.headers
            content = response.text.lower()
            
            # Web servers
            if 'server' in headers:
                technologies['web_servers'].append(headers['server'])
            
            # Programming languages
            if 'x-powered-by' in headers:
                technologies['programming_languages'].append(headers['x-powered-by'])
            
            # CMS detection
            cms_signatures = {
                'WordPress': ['wp-content', 'wp-includes', 'wp-json'],
                'Drupal': ['drupal', 'sites/default', 'node/add'],
                'Joomla': ['joomla', 'option=com_', 'view=article'],
                'Magento': ['magento', 'mage', 'varien'],
                'Shopify': ['shopify', 'cdn.shopify.com'],
                'Wix': ['wix.com', 'parastorage.com']
            }
            
            for cms, signatures in cms_signatures.items():
                if any(sig in content for sig in signatures):
                    technologies['cms'].append(cms)
            
            # Framework detection
            framework_signatures = {
                'React': ['react', 'reactdom', '__react'],
                'Angular': ['ng-app', 'angular', 'ng-controller'],
                'Vue.js': ['vue', 'v-if', 'v-for'],
                'Django': ['django', 'csrfmiddlewaretoken'],
                'Laravel': ['laravel', 'laravel_session'],
                'Ruby on Rails': ['rails', 'authenticity_token'],
                'ASP.NET': ['asp.net', '__viewstate', '__eventvalidation'],
                'Express.js': ['express', 'x-powered-by: express']
            }
            
            for framework, signatures in framework_signatures.items():
                if any(sig in content for sig in signatures):
                    technologies['frameworks'].append(framework)
            
            # Analytics
            analytics_signatures = {
                'Google Analytics': ['google-analytics.com', 'ga.js', 'gtag'],
                'Google Tag Manager': ['googletagmanager.com', 'gtm.js'],
                'Facebook Pixel': ['facebook.com/tr', 'fbevents.js'],
                'Matomo': ['matomo', 'piwik'],
                'Hotjar': ['hotjar.com', '_hjid'],
                'Mixpanel': ['mixpanel.com', 'mixpanel']
            }
            
            for analytics, signatures in analytics_signatures.items():
                if any(sig in content for sig in signatures):
                    technologies['analytics'].append(analytics)
            
        except:
            pass
        
        # Remove duplicates
        for key in technologies:
            technologies[key] = list(set(technologies[key]))
        
        return technologies
    
    def _find_email_addresses(self, domain: str) -> List[str]:
        """Find email addresses associated with the domain"""
        emails = set()
        
        # From WHOIS
        whois_data = self._get_whois(domain)
        if isinstance(whois_data, dict) and 'emails' in whois_data:
            if whois_data['emails']:
                emails.update(whois_data['emails'])
        
        # From website
        try:
            response = self.session.get(f"https://{domain}", timeout=10)
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            found_emails = re.findall(email_pattern, response.text)
            emails.update(found_emails)
        except:
            pass
        
        return list(emails)
    
    def _find_related_domains(self, domain: str) -> List[str]:
        """Find potentially related domains"""
        related = set()
        
        # Check common variations
        base = domain.split('.')[0]
        tlds = ['.com', '.net', '.org', '.io', '.co', '.biz', '.info']
        
        for tld in tlds:
            if not domain.endswith(tld):
                related.add(base + tld)
        
        # Check with/without www
        if domain.startswith('www.'):
            related.add(domain[4:])
        else:
            related.add('www.' + domain)
        
        # Filter out non-existent domains
        valid_related = []
        for rel_domain in related:
            try:
                socket.gethostbyname(rel_domain)
                valid_related.append(rel_domain)
            except:
                pass
        
        return valid_related
    
    def _get_historical_data(self, domain: str) -> Dict[str, Any]:
        """Get historical data about the domain"""
        historical = {
            'archive_snapshots': [],
            'dns_history': []
        }
        
        # Wayback Machine
        try:
            response = self.session.get(
                f"http://archive.org/wayback/available?url={domain}",
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                if 'archived_snapshots' in data:
                    historical['archive_snapshots'] = data['archived_snapshots']
        except:
            pass
        
        return historical
    
    def _check_security_headers(self, domain: str) -> Dict[str, Any]:
        """Check security headers"""
        security_headers = {
            'present': [],
            'missing': [],
            'analysis': {}
        }
        
        important_headers = {
            'Strict-Transport-Security': 'HSTS',
            'X-Frame-Options': 'Clickjacking Protection',
            'X-Content-Type-Options': 'MIME Sniffing Protection',
            'Content-Security-Policy': 'CSP',
            'X-XSS-Protection': 'XSS Protection',
            'Referrer-Policy': 'Referrer Control',
            'Permissions-Policy': 'Feature Control'
        }
        
        try:
            response = self.session.get(f"https://{domain}", timeout=10)
            headers = response.headers
            
            for header, description in important_headers.items():
                if header in headers:
                    security_headers['present'].append({
                        'header': header,
                        'value': headers[header],
                        'description': description
                    })
                else:
                    security_headers['missing'].append({
                        'header': header,
                        'description': description
                    })
            
            # Security score
            score = len(security_headers['present']) / len(important_headers) * 100
            security_headers['score'] = round(score, 2)
            
        except:
            security_headers['error'] = 'Could not check security headers'
        
        return security_headers
    
    def _scan_common_ports(self, domain: str) -> List[Dict[str, Any]]:
        """Scan common ports"""
        common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            8080: 'HTTP Alternate',
            8443: 'HTTPS Alternate'
        }
        
        open_ports = []
        
        def check_port(port_info):
            port, service = port_info
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            try:
                result = sock.connect_ex((domain, port))
                sock.close()
                if result == 0:
                    return {'port': port, 'service': service, 'state': 'open'}
            except:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(check_port, common_ports.items())
            open_ports = [r for r in results if r is not None]
        
        return open_ports
    
    def _detect_cdn(self, domain: str) -> Dict[str, Any]:
        """Detect CDN usage"""
        cdn_info = {
            'detected': False,
            'provider': None,
            'evidence': []
        }
        
        cdn_patterns = {
            'Cloudflare': ['cloudflare', 'cf-ray'],
            'Akamai': ['akamai', 'akamaiedge'],
            'CloudFront': ['cloudfront', 'x-amz-cf-id'],
            'Fastly': ['fastly', 'x-served-by'],
            'MaxCDN': ['maxcdn', 'netdna'],
            'Incapsula': ['incapsula', 'incap_ses'],
            'Sucuri': ['sucuri', 'x-sucuri-id']
        }
        
        try:
            response = self.session.get(f"https://{domain}", timeout=10)
            headers_str = str(response.headers).lower()
            
            for cdn, patterns in cdn_patterns.items():
                for pattern in patterns:
                    if pattern in headers_str:
                        cdn_info['detected'] = True
                        cdn_info['provider'] = cdn
                        cdn_info['evidence'].append(f"Found '{pattern}' in headers")
                        break
        except:
            pass
        
        return cdn_info
    
    def _detect_waf(self, domain: str) -> Dict[str, Any]:
        """Detect Web Application Firewall"""
        waf_info = {
            'detected': False,
            'provider': None,
            'evidence': []
        }
        
        # Send potentially malicious request to trigger WAF
        test_payloads = [
            "/?test=<script>alert(1)</script>",
            "/?id=1' OR '1'='1",
            "/?file=../../../etc/passwd"
        ]
        
        waf_signatures = {
            'Cloudflare': ['cloudflare', 'cf-ray', '1020'],
            'AWS WAF': ['awswaf', 'x-amzn-requestid'],
            'Akamai': ['akamai', 'akamaighost'],
            'Barracuda': ['barracuda', 'barra'],
            'F5 BIG-IP': ['f5-bigip', 'bigipserver'],
            'ModSecurity': ['mod_security', 'modsecurity'],
            'Sucuri': ['sucuri', 'x-sucuri-id'],
            'Wordfence': ['wordfence', 'wfblocked']
        }
        
        try:
            for payload in test_payloads:
                response = self.session.get(f"https://{domain}{payload}", timeout=5)
                response_text = response.text.lower()
                headers_str = str(response.headers).lower()
                
                for waf, signatures in waf_signatures.items():
                    for sig in signatures:
                        if sig in response_text or sig in headers_str:
                            waf_info['detected'] = True
                            waf_info['provider'] = waf
                            waf_info['evidence'].append(f"Found '{sig}' signature")
                            return waf_info
        except:
            pass
        
        return waf_info
