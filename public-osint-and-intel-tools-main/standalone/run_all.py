#!/usr/bin/env python3
"""
Run All OSINT Tools - Master Script
Lackadaisical Security - https://lackadaisical-security.com/
Orchestrates multiple standalone OSINT tools
"""

import os
import sys
import subprocess
import json
import time
from pathlib import Path
import argparse

class OSINTOrchestrator:
    def __init__(self):
        self.script_dir = Path(__file__).parent
        self.output_dir = self.script_dir / "output"
        self.output_dir.mkdir(exist_ok=True)
        
        self.tools = {
            'domain_recon': {
                'script': 'domain_recon.py',
                'command': ['python3', 'domain_recon.py'],
                'type': 'domain'
            },
            'email_hunter': {
                'script': 'email_hunter.py',
                'command': ['python3', 'email_hunter.py'],
                'type': 'domain'
            },
            'port_scanner': {
                'script': 'portscanner.js',
                'command': ['node', 'portscanner.js'],
                'type': 'host'
            },
            'dns_lookup': {
                'script': 'dns_lookup.ps1',
                'command': ['powershell', '-ExecutionPolicy', 'Bypass', '-File', 'dns_lookup.ps1', '-Domain'],
                'type': 'domain'
            },
            'whois_lookup': {
                'script': 'whois_lookup.sh',
                'command': ['bash', 'whois_lookup.sh'],
                'type': 'domain'
            },
            'ip_geolocator': {
                'script': 'ip_geolocator.rb',
                'command': ['ruby', 'ip_geolocator.rb'],
                'type': 'ip'
            },
            'http_headers': {
                'script': 'http_headers.php',
                'command': ['php', 'http_headers.php'],
                'type': 'url'
            }
        }
    
    def print_banner(self):
        banner = """
╔═══════════════════════════════════════════════════════════╗
║           OSINT Orchestrator - Master Script             ║
║                 Lackadaisical Security                    ║
║           https://lackadaisical-security.com/             ║
╚═══════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def check_dependencies(self):
        """Check if required interpreters are available"""
        print("[*] Checking dependencies...")
        
        interpreters = {
            'python3': ['python3', '--version'],
            'node': ['node', '--version'],
            'ruby': ['ruby', '--version'],
            'php': ['php', '--version'],
            'bash': ['bash', '--version'],
            'powershell': ['powershell', '-Command', 'Get-Host']
        }
        
        available = {}
        for name, cmd in interpreters.items():
            try:
                result = subprocess.run(cmd, capture_output=True, timeout=5)
                available[name] = result.returncode == 0
                status = "✓" if available[name] else "✗"
                print(f"  {status} {name}")
            except:
                available[name] = False
                print(f"  ✗ {name}")
        
        return available
    
    def run_tool(self, tool_name, target, available_deps):
        """Run a specific tool"""
        tool = self.tools[tool_name]
        script_path = self.script_dir / tool['script']
        
        if not script_path.exists():
            print(f"[-] Script not found: {tool['script']}")
            return False
        
        # Check if interpreter is available
        interpreter = tool['command'][0]
        if interpreter not in available_deps or not available_deps[interpreter]:
            print(f"[-] Interpreter not available: {interpreter}")
            return False
        
        print(f"\n[*] Running {tool_name}...")
        print("-" * 50)
        
        try:
            # Prepare command
            cmd = tool['command'].copy()
            
            # Handle different parameter styles
            if tool_name == 'dns_lookup':
                cmd.append(target)
            elif tool_name == 'port_scanner':
                cmd.extend([target, "1", "1000", "20"])
            else:
                cmd.append(target)
            
            # Run the tool
            result = subprocess.run(
                cmd,
                cwd=self.script_dir,
                timeout=300,  # 5 minute timeout
                capture_output=False
            )
            
            if result.returncode == 0:
                print(f"[+] {tool_name} completed successfully")
                return True
            else:
                print(f"[-] {tool_name} failed with exit code {result.returncode}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"[-] {tool_name} timed out")
            return False
        except Exception as e:
            print(f"[-] Error running {tool_name}: {e}")
            return False
    
    def run_all_for_target(self, target, target_type="auto"):
        """Run all applicable tools for a target"""
        print(f"\n[*] Starting comprehensive scan for: {target}")
        print(f"[*] Target type: {target_type}")
        
        available_deps = self.check_dependencies()
        
        # Determine target type if auto
        if target_type == "auto":
            if target.startswith(('http://', 'https://')):
                target_type = "url"
            elif self._is_ip(target):
                target_type = "ip"
            else:
                target_type = "domain"
        
        # Run applicable tools
        results = {}
        for tool_name, tool_info in self.tools.items():
            if tool_info['type'] == target_type or tool_info['type'] in ['domain', 'host']:
                success = self.run_tool(tool_name, target, available_deps)
                results[tool_name] = success
        
        # Summary
        print("\n" + "="*60)
        print("SCAN SUMMARY")
        print("="*60)
        print(f"Target: {target}")
        print(f"Type: {target_type}")
        
        successful = sum(1 for success in results.values() if success)
        total = len(results)
        print(f"Tools run: {successful}/{total}")
        
        for tool_name, success in results.items():
            status = "✓" if success else "✗"
            print(f"  {status} {tool_name}")
        
        return results
    
    def _is_ip(self, target):
        """Check if target is an IP address"""
        import re
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return re.match(ip_pattern, target) is not None

def main():
    parser = argparse.ArgumentParser(
        description='OSINT Orchestrator - Run multiple OSINT tools',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 run_all.py example.com
  python3 run_all.py 8.8.8.8 --type ip
  python3 run_all.py https://example.com --type url
        """
    )
    
    parser.add_argument('target', help='Target to scan (domain, IP, or URL)')
    parser.add_argument('--type', choices=['domain', 'ip', 'url', 'auto'], 
                       default='auto', help='Target type')
    
    args = parser.parse_args()
    
    orchestrator = OSINTOrchestrator()
    orchestrator.print_banner()
    
    results = orchestrator.run_all_for_target(args.target, args.type)
    
    # Save orchestrator results
    output_file = orchestrator.output_dir / f"orchestrator_{int(time.time())}.json"
    with open(output_file, 'w') as f:
        json.dump({
            'target': args.target,
            'type': args.type,
            'timestamp': time.time(),
            'results': results
        }, f, indent=2)
    
    print(f"\n[+] Orchestrator results saved to: {output_file}")
    print("\n" + "="*60)
    print("Lackadaisical Security")
    print("https://lackadaisical-security.com/")
    print("="*60)

if __name__ == "__main__":
    main()
