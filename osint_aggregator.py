import asyncio
import aiohttp
from typing import Dict, List, Any
import json
from datetime import datetime

class OSINTAggregator:
    """Aggregate threat intelligence from legitimate public sources"""
    
    def __init__(self):
        self.sources = {
            "phishtank": {
                "url": "http://data.phishtank.com/data/online-valid.json",
                "type": "phishing"
            },
            "cert_feeds": {
                "url": "https://www.cert.org/feed/",
                "type": "advisories"
            },
            "cisa_alerts": {
                "url": "https://www.cisa.gov/cybersecurity-advisories",
                "type": "gov_advisories"
            }
        }
        
        self.collected_data = {
            "timestamp": datetime.now().isoformat(),
            "sources": {},
            "aggregated_iocs": {
                "domains": set(),
                "ips": set(),
                "urls": set(),
                "hashes": set()
            }
        }
    
    async def fetch_feed(self, session: aiohttp.ClientSession, source_name: str, source_info: Dict) -> Dict:
        """Fetch data from a single feed"""
        try:
            async with session.get(source_info["url"]) as response:
                if response.status == 200:
                    data = await response.text()
                    return {
                        "source": source_name,
                        "data": data,
                        "success": True
                    }
        except Exception as e:
            print(f"Error fetching {source_name}: {e}")
        
        return {"source": source_name, "success": False}
    
    async def aggregate_all_sources(self):
        """Fetch data from all configured sources concurrently"""
        async with aiohttp.ClientSession() as session:
            tasks = []
            for source_name, source_info in self.sources.items():
                task = self.fetch_feed(session, source_name, source_info)
                tasks.append(task)
            
            results = await asyncio.gather(*tasks)
            
            for result in results:
                if result["success"]:
                    self.collected_data["sources"][result["source"]] = {
                        "collected_at": datetime.now().isoformat(),
                        "status": "success"
                    }
    
    def search_keyword_in_feeds(self, keyword: str) -> List[Dict]:
        """Search for specific keywords across all collected feeds"""
        matches = []
        
        for source, data in self.collected_data["sources"].items():
            # Implement keyword search logic here
            # This is a template - actual implementation depends on feed format
            pass
        
        return matches
    
    def export_findings(self, filename: str = "osint_findings.json"):
        """Export aggregated findings to JSON file"""
        # Convert sets to lists for JSON serialization
        export_data = self.collected_data.copy()
        export_data["aggregated_iocs"] = {
            k: list(v) for k, v in self.collected_data["aggregated_iocs"].items()
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        print(f"Findings exported to {filename}")

# Usage example
async def main():
    aggregator = OSINTAggregator()
    await aggregator.aggregate_all_sources()
    aggregator.export_findings()

if __name__ == "__main__":
    asyncio.run(main())
