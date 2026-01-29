import requests
import socket
from typing import Dict, Any
from config import Config

class IPIntel:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': Config.USER_AGENT})
        
    def gather_intel(self, ip_address: str) -> Dict[str, Any]:
        """Gather intelligence about an IP address"""
        results = {
            'ip': ip_address,
            'hostname': None,
            'geolocation': None,
            'asn_info': None,
            'reputation': None,
            'open_ports': []
        }
        
        # Reverse DNS
        try:
            results['hostname'] = socket.gethostbyaddr(ip_address)[0]
        except:
            results['hostname'] = "No reverse DNS"
            
        # Geolocation using free API
        results['geolocation'] = self._get_geolocation(ip_address)
        
        # ASN information
        results['asn_info'] = self._get_asn_info(ip_address)
        
        return results
    
    def _get_geolocation(self, ip: str) -> Dict[str, Any]:
        """Get geolocation data"""
        try:
            response = self.session.get(f"http://ip-api.com/json/{ip}")
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country'),
                    'region': data.get('regionName'),
                    'city': data.get('city'),
                    'lat': data.get('lat'),
                    'lon': data.get('lon'),
                    'isp': data.get('isp'),
                    'org': data.get('org')
                }
        except:
            pass
        return {'error': 'Could not fetch geolocation'}
    
    def _get_asn_info(self, ip: str) -> Dict[str, Any]:
        """Get ASN information"""
        try:
            response = self.session.get(f"https://api.hackertarget.com/aslookup/?q={ip}")
            if response.status_code == 200:
                lines = response.text.strip().split('\n')
                if lines and ',' in lines[0]:
                    parts = lines[0].split(',')
                    return {
                        'asn': parts[0].strip('"'),
                        'range': parts[1].strip('"'),
                        'name': parts[2].strip('"') if len(parts) > 2 else 'Unknown'
                    }
        except:
            pass
        return {'error': 'Could not fetch ASN info'}
