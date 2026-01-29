import requests
import socket
import ipaddress
import concurrent.futures
from typing import Dict, Any, List
from datetime import datetime
import struct
import json
from config import Config

class AdvancedIPIntel:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': Config.USER_AGENT})
        
    def gather_intel(self, ip_address: str) -> Dict[str, Any]:
        """Gather comprehensive intelligence about an IP address"""
        # Validate IP
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            return {'error': 'Invalid IP address format'}
        
        results = {
            'ip': ip_address,
            'timestamp': datetime.now().isoformat(),
            'basic_info': self._get_basic_info(ip_address),
            'geolocation': self._get_detailed_geolocation(ip_address),
            'asn_info': self._get_detailed_asn_info(ip_address),
            'reverse_dns': self._get_reverse_dns(ip_address),
            'open_ports': self._scan_ports(ip_address),
            'services': self._detect_services(ip_address),
            'blacklist_check': self._check_blacklists(ip_address),
            'threat_intelligence': self._get_threat_intel(ip_address),
            'related_domains': self._find_related_domains(ip_address),
            'network_info': self._get_network_info(ip_address),
            'ssl_certificates': self._get_ssl_certificates(ip_address),
            'historical_data': self._get_historical_data(ip_address),
            'bgp_info': self._get_bgp_info(ip_address),
            'reputation_score': self._calculate_reputation(ip_address)
        }
        
        # Add Shodan data if API key is available
        if Config.SHODAN_API_KEY:
            results['shodan_data'] = self._get_shodan_data(ip_address)
        
        return results
    
    def _get_basic_info(self, ip: str) -> Dict[str, Any]:
        """Get basic IP information"""
        info = {
            'version': 4 if '.' in ip else 6,
            'type': 'Unknown',
            'decimal': self._ip_to_decimal(ip)
        }
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            info['type'] = 'Private' if ip_obj.is_private else 'Public'
            info['is_reserved'] = ip_obj.is_reserved
            info['is_loopback'] = ip_obj.is_loopback
            info['is_multicast'] = ip_obj.is_multicast
            
            if hasattr(ip_obj, 'is_global'):
                info['is_global'] = ip_obj.is_global
        except:
            pass
        
        return info
    
    def _ip_to_decimal(self, ip: str) -> int:
        """Convert IP to decimal"""
        try:
            if '.' in ip:  # IPv4
                parts = ip.split('.')
                return int(parts[0]) * 16777216 + int(parts[1]) * 65536 + \
                       int(parts[2]) * 256 + int(parts[3])
            else:  # IPv6
                return int(ipaddress.ip_address(ip))
        except:
            return 0
    
    def _get_detailed_geolocation(self, ip: str) -> Dict[str, Any]:
        """Get detailed geolocation from multiple sources"""
        geo_data = {}
        
        # Primary source: ip-api.com
        try:
            response = self.session.get(
                f"http://ip-api.com/json/{ip}?fields=66846719",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    geo_data = {
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'region': data.get('regionName'),
                        'region_code': data.get('region'),
                        'city': data.get('city'),
                        'zip': data.get('zip'),
                        'lat': data.get('lat'),
                        'lon': data.get('lon'),
                        'timezone': data.get('timezone'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'as': data.get('as'),
                        'asname': data.get('asname'),
                        'mobile': data.get('mobile'),
                        'proxy': data.get('proxy'),
                        'hosting': data.get('hosting')
                    }
        except:
            pass
        
        # Backup source: ipapi.co
        if not geo_data:
            try:
                response = self.session.get(
                    f"https://ipapi.co/{ip}/json/",
                    timeout=5
                )
                if response.status_code == 200:
                    data = response.json()
                    geo_data = {
                        'country': data.get('country_name'),
                        'country_code': data.get('country_code'),
                        'region': data.get('region'),
                        'city': data.get('city'),
                        'lat': data.get('latitude'),
                        'lon': data.get('longitude'),
                        'timezone': data.get('timezone'),
                        'org': data.get('org')
                    }
            except:
                pass
        
        return geo_data or {'error': 'Could not fetch geolocation'}
    
    def _get_detailed_asn_info(self, ip: str) -> Dict[str, Any]:
        """Get detailed ASN information"""
        asn_info = {}
        
        # Try multiple sources
        sources = [
            {
                'url': f"https://api.hackertarget.com/aslookup/?q={ip}",
                'parser': self._parse_hackertarget_asn
            },
            {
                'url': f"https://api.bgpview.io/ip/{ip}",
                'parser': self._parse_bgpview_asn
            }
        ]
        
        for source in sources:
            try:
                response = self.session.get(source['url'], timeout=5)
                if response.status_code == 200:
                    asn_info = source['parser'](response)
                    if asn_info:
                        break
            except:
                continue
        
        return asn_info or {'error': 'Could not fetch ASN info'}
    
    def _parse_hackertarget_asn(self, response) -> Dict[str, Any]:
        """Parse HackerTarget ASN response"""
        try:
            lines = response.text.strip().split('\n')
            if lines and ',' in lines[0]:
                parts = lines[0].split(',')
                return {
                    'asn': parts[0].strip('"').replace('AS', ''),
                    'range': parts[1].strip('"'),
                    'name': parts[2].strip('"') if len(parts) > 2 else 'Unknown',
                    'source': 'hackertarget'
                }
        except:
            pass
        return {}
    
    def _parse_bgpview_asn(self, response) -> Dict[str, Any]:
        """Parse BGPView ASN response"""
        try:
            data = response.json()
            if data.get('status') == 'ok':
                result = data.get('data', {})
                prefixes = result.get('prefixes', [])
                if prefixes:
                    prefix = prefixes[0]
                    asn = prefix.get('asn', {})
                    return {
                        'asn': asn.get('asn'),
                        'name': asn.get('name'),
                        'description': asn.get('description'),
                        'country_code': asn.get('country_code'),
                        'prefix': prefix.get('prefix'),
                        'source': 'bgpview'
                    }
        except:
            pass
        return {}
    
    def _get_reverse_dns(self, ip: str) -> List[str]:
        """Get all reverse DNS records"""
        hostnames = []
        
        try:
            # Standard reverse DNS
            hostname = socket.gethostbyaddr(ip)[0]
            hostnames.append(hostname)
            
            # Try to get all PTR records
            reverse_ip = '.'.join(reversed(ip.split('.'))) + '.in-addr.arpa'
            import dns.resolver
            resolver = dns.resolver.Resolver()
            
            try:
                answers = resolver.resolve(reverse_ip, 'PTR')
                for rdata in answers:
                    hostname = str(rdata).rstrip('.')
                    if hostname not in hostnames:
                        hostnames.append(hostname)
            except:
                pass
                
        except:
            pass
        
        return hostnames or ['No reverse DNS found']
    
    def _scan_ports(self, ip: str) -> List[Dict[str, Any]]:
        """Scan common ports with service detection"""
        # Extended port list with service names
        port_services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'RPC-DCOM', 139: 'NetBIOS',
            143: 'IMAP', 161: 'SNMP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
            587: 'SMTP-Submission', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
            1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt',
            9200: 'Elasticsearch', 27017: 'MongoDB'
        }
        
        open_ports = []
        
        def scan_port(port_info):
            port, service = port_info
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            try:
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    # Try to grab banner
                    banner = self._grab_banner(ip, port)
                    return {
                        'port': port,
                        'service': service,
                        'state': 'open',
                        'banner': banner
                    }
            except:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            results = executor.map(scan_port, port_services.items())
            open_ports = [r for r in results if r is not None]
        
        return open_ports
    
    def _grab_banner(self, ip: str, port: int) -> str:
        """Attempt to grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            
            # Send probe for different services
            if port in [80, 8080, 8443]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 21:
                pass  # FTP sends banner automatically
            elif port == 22:
                pass  # SSH sends banner automatically
            elif port == 25:
                pass  # SMTP sends banner automatically
            else:
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:200]  # Limit banner length
        except:
            return ""
    
    def _detect_services(self, ip: str) -> List[Dict[str, Any]]:
        """Detect running services based on open ports and banners"""
        services = []
        open_ports = self._scan_ports(ip)
        
        for port_info in open_ports:
            service = {
                'port': port_info['port'],
                'name': port_info['service'],
                'version': 'Unknown',
                'details': {}
            }
            
            # Parse banner for version info
            banner = port_info.get('banner', '')
            if banner:
                # SSH version
                if 'SSH' in banner:
                    import re
                    ssh_match = re.search(r'SSH-[\d.]+-(.+)', banner)
                    if ssh_match:
                        service['version'] = ssh_match.group(1)
                
                # HTTP server
                elif 'HTTP' in banner:
                    if 'Server:' in banner:
                        server_match = re.search(r'Server:\s*(.+)', banner)
                        if server_match:
                            service['version'] = server_match.group(1).strip()
                
                # FTP server
                elif port_info['port'] == 21 and '220' in banner:
                    service['version'] = banner.split('220')[1].strip()
                
                # SMTP server
                elif port_info['port'] == 25 and '220' in banner:
                    service['version'] = banner.split('220')[1].strip()
            
            services.append(service)
        
        return services
    
    def _check_blacklists(self, ip: str) -> Dict[str, Any]:
        """Check IP against various blacklists"""
        blacklists = {
            'spamhaus': 'zen.spamhaus.org',
            'barracuda': 'b.barracudacentral.org',
            'spamcop': 'bl.spamcop.net',
            'surbl': 'multi.surbl.org',
            'uceprotect': 'dnsbl-1.uceprotect.net'
        }
        
        results = {
            'listed': False,
            'lists': [],
            'clean_lists': []
        }
        
        reversed_ip = '.'.join(reversed(ip.split('.')))
        
        for name, bl_domain in blacklists.items():
            try:
                query = f"{reversed_ip}.{bl_domain}"
                socket.gethostbyname(query)
                # If we get a response, IP is listed
                results['listed'] = True
                results['lists'].append(name)
            except socket.gaierror:
                # No response means not listed
                results['clean_lists'].append(name)
        
        results['reputation'] = 'Poor' if results['listed'] else 'Good'
        results['listed_count'] = len(results['lists'])
        results['clean_count'] = len(results['clean_lists'])
        
        return results
    
    def _get_threat_intel(self, ip: str) -> Dict[str, Any]:
        """Get threat intelligence from various sources"""
        threat_data = {
            'is_threat': False,
            'threat_level': 'Low',
            'categories': [],
            'sources': []
        }
        
        # Check AbuseIPDB (requires API key for full functionality)
        try:
            response = self.session.get(
                f"https://api.abuseipdb.com/api/v2/check",
                headers={'Key': Config.ABUSEIPDB_KEY} if hasattr(Config, 'ABUSEIPDB_KEY') else {},
                params={'ipAddress': ip},
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('data', {}).get('abuseConfidenceScore', 0) > 25:
                    threat_data['is_threat'] = True
                    threat_data['sources'].append('AbuseIPDB')
        except:
            pass
        
        # Check against known malicious IP ranges
        malicious_ranges = [
            '10.0.0.0/8',  # Example - replace with actual threat feeds
            '192.168.0.0/16',
            '172.16.0.0/12'
        ]
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            for range_str in malicious_ranges:
                if ip_obj in ipaddress.ip_network(range_str, strict=False):
                    threat_data['categories'].append('Known malicious range')
                    break
        except:
            pass
        
        # Set threat level based on findings
        if threat_data['is_threat']:
            threat_data['threat_level'] = 'High'
        elif threat_data['categories']:
            threat_data['threat_level'] = 'Medium'
        
        return threat_data
    
    def _find_related_domains(self, ip: str) -> List[Dict[str, str]]:
        """Find domains hosted on the same IP"""
        domains = []
        
        # Use reverse IP lookup services
        try:
            # Bing reverse IP search
            response = self.session.get(
                f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
                timeout=10
            )
            if response.status_code == 200:
                for domain in response.text.strip().split('\n'):
                    if domain and not domain.startswith('error'):
                        domains.append({
                            'domain': domain,
                            'source': 'hackertarget'
                        })
        except:
            pass
        
        return domains[:50]  # Limit results
    
    def _get_network_info(self, ip: str) -> Dict[str, Any]:
        """Get network information"""
        network_info = {
            'network': None,
            'netmask': None,
            'broadcast': None,
            'first_host': None,
            'last_host': None,
            'num_hosts': 0
        }
        
        try:
            # Get network from ASN info
            asn_info = self._get_detailed_asn_info(ip)
            if 'range' in asn_info:
                network = ipaddress.ip_network(asn_info['range'], strict=False)
                network_info.update({
                    'network': str(network.network_address),
                    'netmask': str(network.netmask),
                    'broadcast': str(network.broadcast_address),
                    'first_host': str(list(network.hosts())[0]) if network.num_addresses > 2 else None,
                    'last_host': str(list(network.hosts())[-1]) if network.num_addresses > 2 else None,
                    'num_hosts': network.num_addresses - 2 if network.num_addresses > 2 else 0
                })
        except:
            pass
        
        return network_info
    
    def _get_ssl_certificates(self, ip: str) -> List[Dict[str, Any]]:
        """Get SSL certificates from the IP"""
        certificates = []
        ssl_ports = [443, 8443, 993, 995, 465, 587]
        
        for port in ssl_ports:
            try:
                import ssl
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((ip, port), timeout=3) as sock:
                    with context.wrap_socket(sock) as ssock:
                        cert = ssock.getpeercert()
                        if cert:
                            certificates.append({
                                'port': port,
                                'subject': dict(x[0] for x in cert.get('subject', [])),
                                'issuer': dict(x[0] for x in cert.get('issuer', [])),
                                'version': cert.get('version'),
                                'not_before': cert.get('notBefore'),
                                'not_after': cert.get('notAfter'),
                                'san': cert.get('subjectAltName', [])
                            })
            except:
                pass
        
        return certificates
    
    def _get_historical_data(self, ip: str) -> Dict[str, Any]:
        """Get historical data about the IP"""
        historical = {
            'first_seen': None,
            'last_seen': datetime.now().isoformat(),
            'changes': []
        }
        
        # This would typically query historical databases
        # For now, return basic structure
        return historical
    
    def _get_bgp_info(self, ip: str) -> Dict[str, Any]:
        """Get BGP routing information"""
        bgp_info = {}
        
        try:
            response = self.session.get(
                f"https://api.bgpview.io/ip/{ip}",
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'ok':
                    result = data.get('data', {})
                    bgp_info = {
                        'prefixes': result.get('prefixes', []),
                        'rir_allocation': result.get('rir_allocation', {}),
                        'maxmind': result.get('maxmind', {})
                    }
        except:
            pass
        
        return bgp_info
    
    def _calculate_reputation(self, ip: str) -> Dict[str, Any]:
        """Calculate overall reputation score"""
        score = 100  # Start with perfect score
        factors = []
        
        # Check blacklists
        blacklist_check = self._check_blacklists(ip)
        if blacklist_check['listed']:
            score -= 30
            factors.append(f"Listed in {blacklist_check['listed_count']} blacklists")
        
        # Check if it's a known proxy/VPN
        geo_data = self._get_detailed_geolocation(ip)
        if geo_data.get('proxy'):
            score -= 20
            factors.append("Detected as proxy")
        
        # Check open ports
        open_ports = self._scan_ports(ip)
        risky_ports = [23, 135, 139, 445, 1433, 3389]  # Telnet, RPC, SMB, MSSQL, RDP
        for port_info in open_ports:
            if port_info['port'] in risky_ports:
                score -= 10
                factors.append(f"Risky port {port_info['port']} open")
        
        # Determine reputation level
        if score >= 80:
            level = 'Excellent'
        elif score >= 60:
            level = 'Good'
        elif score >= 40:
            level = 'Fair'
        elif score >= 20:
            level = 'Poor'
        else:
            level = 'Very Poor'
        
        return {
            'score': max(0, score),
            'level': level,
            'factors': factors
        }
    
    def _get_shodan_data(self, ip: str) -> Dict[str, Any]:
        """Get data from Shodan if API key is available"""
        try:
            import shodan
            api = shodan.Shodan(Config.SHODAN_API_KEY)
            host = api.host(ip)
            
            return {
                'last_update': host.get('last_update'),
                'ports': host.get('ports', []),
                'vulns': host.get('vulns', []),
                'hostnames': host.get('hostnames', []),
                'tags': host.get('tags', []),
                'os': host.get('os'),
                'services': [
                    {
                        'port': service.get('port'),
                        'transport': service.get('transport'),
                        'product': service.get('product'),
                        'version': service.get('version'),
                        'cpe': service.get('cpe', [])
                    }
                    for service in host.get('data', [])
                ]
            }
        except Exception as e:
            return {'error': str(e)}
