#!/usr/bin/env python3
"""
DNS Leak Detection Tool

Standalone script to detect DNS leaks that could compromise anonymity.
Checks if DNS queries are going through expected resolvers or leaking to ISP.
"""

import socket
import dns.resolver
import requests
import json
import sys
from typing import List, Dict, Tuple, Optional

class DNSLeakChecker:
    """DNS leak detection and analysis"""
    
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.original_nameservers = self.resolver.nameservers.copy()
        
    def get_public_ip(self) -> Optional[str]:
        """Get current public IP address"""
        try:
            response = requests.get('https://api.ipify.org?format=json', timeout=10)
            return response.json()['ip']
        except Exception as e:
            print(f"Error getting public IP: {e}")
            return None
    
    def get_dns_servers(self) -> List[str]:
        """Get currently configured DNS servers"""
        return self.resolver.nameservers
    
    def perform_dns_leak_test(self) -> Dict[str, any]:
        """
        Perform comprehensive DNS leak test
        
        Returns dict with test results
        """
        results = {
            'public_ip': None,
            'dns_servers': [],
            'leak_detected': False,
            'queries': []
        }
        
        # Get public IP
        results['public_ip'] = self.get_public_ip()
        results['dns_servers'] = self.get_dns_servers()
        
        # Test DNS queries to unique subdomains
        test_domains = [
            f'test{i}.dnsleaktest.com' for i in range(1, 6)
        ]
        
        for domain in test_domains:
            try:
                answers = self.resolver.resolve(domain, 'A')
                for rdata in answers:
                    results['queries'].append({
                        'domain': domain,
                        'resolved_ip': str(rdata),
                        'status': 'success'
                    })
            except Exception as e:
                results['queries'].append({
                    'domain': domain,
                    'error': str(e),
                    'status': 'failed'
                })
        
        # Check for leaks by comparing DNS servers with expected servers
        # If using VPN/Tor, DNS servers should be VPN/Tor servers, not ISP
        expected_secure_dns = [
            '1.1.1.1',  # Cloudflare
            '1.0.0.1',
            '8.8.8.8',  # Google
            '8.8.4.4',
            '9.9.9.9',  # Quad9
            '149.112.112.112'
        ]
        
        # Check if any DNS server is a known secure resolver
        using_secure_dns = any(
            dns_server in expected_secure_dns 
            for dns_server in results['dns_servers']
        )
        
        # Simple leak detection: if not using known secure DNS, might be ISP leak
        if not using_secure_dns and len(results['dns_servers']) > 0:
            # Check if DNS server is in private IP range (could be VPN)
            is_private = all(
                self._is_private_ip(dns_server) 
                for dns_server in results['dns_servers']
            )
            if not is_private:
                results['leak_detected'] = True
        
        return results
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            parts = [int(p) for p in ip.split('.')]
            # 10.0.0.0/8
            if parts[0] == 10:
                return True
            # 172.16.0.0/12
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            # 192.168.0.0/16
            if parts[0] == 192 and parts[1] == 168:
                return True
            # 127.0.0.0/8 (localhost)
            if parts[0] == 127:
                return True
            return False
        except:
            return False
    
    def check_webrtc_leak(self) -> Dict[str, str]:
        """
        Check for WebRTC IP leaks (requires external service)
        
        Returns warning about WebRTC
        """
        return {
            'warning': 'WebRTC can leak real IP even through VPN',
            'mitigation': 'Disable WebRTC in browser or use browser extension',
            'test_url': 'https://browserleaks.com/webrtc'
        }
    
    def generate_report(self, results: Dict[str, any]) -> str:
        """Generate human-readable report"""
        report = []
        report.append("=" * 60)
        report.append("DNS LEAK DETECTION REPORT")
        report.append("=" * 60)
        report.append(f"\nPublic IP: {results['public_ip']}")
        report.append(f"\nConfigured DNS Servers:")
        for server in results['dns_servers']:
            report.append(f"  - {server}")
        
        report.append(f"\nDNS Query Tests:")
        for query in results['queries']:
            if query['status'] == 'success':
                report.append(f"  ✓ {query['domain']} -> {query['resolved_ip']}")
            else:
                report.append(f"  ✗ {query['domain']} -> {query.get('error', 'Unknown error')}")
        
        report.append(f"\n{'=' * 60}")
        if results['leak_detected']:
            report.append("⚠ WARNING: POTENTIAL DNS LEAK DETECTED")
            report.append("Your DNS queries may be going through your ISP")
            report.append("instead of your VPN/proxy DNS servers.")
            report.append("\nRecommendations:")
            report.append("  1. Configure VPN to use VPN-provided DNS")
            report.append("  2. Use DNS leak protection features in VPN client")
            report.append("  3. Manually set DNS to 1.1.1.1 or 8.8.8.8")
        else:
            report.append("✓ No obvious DNS leaks detected")
            report.append("However, always verify with online tools:")
            report.append("  - https://dnsleaktest.com")
            report.append("  - https://ipleak.net")
        
        report.append("=" * 60)
        
        return "\n".join(report)


def main():
    """Main execution"""
    print("DNS Leak Detection Tool")
    print("Checking for DNS leaks...\n")
    
    checker = DNSLeakChecker()
    
    # Run leak test
    results = checker.perform_dns_leak_test()
    
    # Generate and print report
    report = checker.generate_report(results)
    print(report)
    
    # Check WebRTC
    print("\n" + "=" * 60)
    print("WEBRTC LEAK WARNING")
    print("=" * 60)
    webrtc = checker.check_webrtc_leak()
    print(f"\n{webrtc['warning']}")
    print(f"Mitigation: {webrtc['mitigation']}")
    print(f"Test at: {webrtc['test_url']}")
    print("=" * 60)
    
    # Export results to JSON
    try:
        with open('dns_leak_report.json', 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n✓ Detailed results saved to: dns_leak_report.json")
    except Exception as e:
        print(f"\n✗ Failed to save report: {e}")
    
    # Exit with appropriate code
    if results['leak_detected']:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
