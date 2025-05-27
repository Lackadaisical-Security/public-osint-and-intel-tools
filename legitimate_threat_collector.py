import requests
import json
from datetime import datetime
import hashlib
import re

class LegitimateTheatIntel:
    """Collect threat intelligence from legitimate public sources"""
    
    def __init__(self):
        self.results = {
            "collection_date": datetime.now().isoformat(),
            "sources": [],
            "indicators": {
                "domains": [],
                "ips": [],
                "hashes": [],
                "urls": []
            }
        }
    
    def search_virustotal_public(self, hash_value):
        """Search VirusTotal using public API (requires free API key)"""
        # Note: User needs to register for free API key at virustotal.com
        api_key = "YOUR_VT_API_KEY"
        url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
        headers = {"x-apikey": api_key}
        
        try:
            # Public API has rate limits - respect them
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            print(f"VT Error: {e}")
        return None
    
    def search_alienvault_otx(self, indicator):
        """Search AlienVault OTX (public threat intelligence)"""
        base_url = "https://otx.alienvault.com/api/v1/indicators"
        # Public API - no authentication required for basic queries
        
        indicator_types = {
            "domain": "domain",
            "ip": "IPv4",
            "hash": "file"
        }
        
        results = []
        for ioc_type, otx_type in indicator_types.items():
            try:
                url = f"{base_url}/{otx_type}/{indicator}/general"
                response = requests.get(url)
                if response.status_code == 200:
                    results.append(response.json())
            except:
                pass
        
        return results
    
    def search_abuse_ch(self, query):
        """Search abuse.ch databases (public threat feeds)"""
        databases = {
            "malwarebazaar": "https://mb-api.abuse.ch/api/v1/",
            "threatfox": "https://threatfox-api.abuse.ch/api/v1/",
            "urlhaus": "https://urlhaus-api.abuse.ch/v1/"
        }
        
        results = {}
        for db_name, api_url in databases.items():
            try:
                # Each database has different query formats
                if db_name == "malwarebazaar":
                    data = {"query": "get_info", "hash": query}
                elif db_name == "threatfox":
                    data = {"query": "search_ioc", "search_term": query}
                else:
                    data = {"url": query}
                
                response = requests.post(api_url, data=data)
                if response.status_code == 200:
                    results[db_name] = response.json()
            except:
                pass
        
        return results
    
    def extract_iocs_from_text(self, text):
        """Extract IOCs from text using regex"""
        ioc_patterns = {
            "domains": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
            "ips": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            "md5": r'\b[a-fA-F0-9]{32}\b',
            "sha256": r'\b[a-fA-F0-9]{64}\b',
            "urls": r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)'
        }
        
        extracted = {}
        for ioc_type, pattern in ioc_patterns.items():
            matches = re.findall(pattern, text)
            extracted[ioc_type] = list(set(matches))
        
        return extracted
    
    def search_public_sandboxes(self, file_hash):
        """Search public malware sandboxes"""
        sandboxes = {
            "hybrid_analysis": f"https://www.hybrid-analysis.com/api/v2/search/hash/{file_hash}",
            "joe_sandbox": f"https://jbxcloud.joesecurity.org/api/v2/analysis/search?q={file_hash}"
        }
        
        # Note: Most require API keys but offer free tiers
        results = {}
        for sandbox, url in sandboxes.items():
            # Add API key handling here
            pass
        
        return results
    
    def generate_report(self, output_file="threat_intel_report.json"):
        """Generate a JSON report of findings"""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"Report saved to {output_file}")
        return self.results

# Example usage
if __name__ == "__main__":
    collector = LegitimateTheatIntel()
    
    # Example: Search for a known malware hash
    # Replace with actual indicators you want to research
    test_hash = "example_hash_here"
    
    # Collect from various sources
    vt_results = collector.search_virustotal_public(test_hash)
    otx_results = collector.search_alienvault_otx(test_hash)
    abuse_results = collector.search_abuse_ch(test_hash)
    
    # Generate report
    collector.generate_report()
