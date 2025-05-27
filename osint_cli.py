#!/usr/bin/env python3
import argparse
import json
from colorama import init, Fore, Style
from tabulate import tabulate
from tools.domain_intel import DomainIntel
from tools.ip_intel import IPIntel
from tools.email_intel import EmailIntel
from tools.web_scraper import WebScraper
from tools.social_media_intel import SocialMediaIntel
from tools.image_intel import ImageIntel

# Initialize colorama
init()

class OSINTToolkit:
    def __init__(self):
        self.domain_intel = DomainIntel()
        self.ip_intel = IPIntel()
        self.email_intel = EmailIntel()
        self.web_scraper = WebScraper()
        self.social_intel = SocialMediaIntel()
        self.image_intel = ImageIntel()
        
    def print_banner(self):
        banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════╗
║             OSINT & Intelligence Gathering Toolkit         ║
║                    Public Edition v1.0                     ║
║           Developed by Lackadaisical Security              ║
╚═══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)
        
    def print_results(self, title: str, data: dict):
        """Pretty print results"""
        print(f"\n{Fore.GREEN}[+] {title}{Style.RESET_ALL}")
        print("="*60)
        
        for key, value in data.items():
            if isinstance(value, dict):
                print(f"\n{Fore.YELLOW}{key}:{Style.RESET_ALL}")
                for k, v in value.items():
                    print(f"  {k}: {v}")
            elif isinstance(value, list):
                print(f"\n{Fore.YELLOW}{key}:{Style.RESET_ALL}")
                if value:
                    for item in value:
                        if isinstance(item, dict):
                            for k, v in item.items():
                                print(f"  - {k}: {v}")
                        else:
                            print(f"  - {item}")
                else:
                    print("  None found")
            else:
                print(f"{Fore.YELLOW}{key}:{Style.RESET_ALL} {value}")
                
    def run_domain_intel(self, domain: str, output_file: str = None):
        """Run domain intelligence gathering"""
        print(f"\n{Fore.CYAN}[*] Gathering intelligence for domain: {domain}{Style.RESET_ALL}")
        results = self.domain_intel.gather_intel(domain)
        
        self.print_results("Domain Intelligence Results", results)
        
        if output_file:
            self._save_results(results, output_file)
            
    def run_ip_intel(self, ip: str, output_file: str = None):
        """Run IP intelligence gathering"""
        print(f"\n{Fore.CYAN}[*] Gathering intelligence for IP: {ip}{Style.RESET_ALL}")
        results = self.ip_intel.gather_intel(ip)
        
        self.print_results("IP Intelligence Results", results)
        
        if output_file:
            self._save_results(results, output_file)
            
    def run_email_intel(self, email: str, output_file: str = None):
        """Run email intelligence gathering"""
        print(f"\n{Fore.CYAN}[*] Gathering intelligence for email: {email}{Style.RESET_ALL}")
        results = self.email_intel.gather_intel(email)
        
        self.print_results("Email Intelligence Results", results)
        
        if output_file:
            self._save_results(results, output_file)
            
    def run_web_scraper(self, url: str, output_file: str = None):
        """Run web scraping intelligence gathering"""
        print(f"\n{Fore.CYAN}[*] Scraping intelligence from: {url}{Style.RESET_ALL}")
        results = self.web_scraper.scrape_intel(url)
        
        self.print_results("Web Scraping Results", results)
        
        if output_file:
            self._save_results(results, output_file)
            
    def run_social_intel(self, username: str, output_file: str = None):
        """Run social media intelligence gathering"""
        print(f"\n{Fore.CYAN}[*] Searching for username across social media: {username}{Style.RESET_ALL}")
        results = self.social_intel.search_username(username)
        
        self.print_results("Social Media Intelligence Results", results)
        
        if output_file:
            self._save_results(results, output_file)
            
    def run_image_intel(self, image_source: str, output_file: str = None):
        """Run image intelligence gathering"""
        print(f"\n{Fore.CYAN}[*] Analyzing image: {image_source}{Style.RESET_ALL}")
        results = self.image_intel.analyze_image(image_source)
        
        # Add reverse search URLs if it's a URL
        if image_source.startswith(('http://', 'https://')):
            results['reverse_search_urls'] = self.image_intel.reverse_image_search_urls(image_source)
        
        self.print_results("Image Intelligence Results", results)
        
        if output_file:
            self._save_results(results, output_file)
    
    def _save_results(self, results: dict, filename: str):
        """Save results to JSON file"""
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n{Fore.GREEN}[+] Results saved to: {filename}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(
        description='OSINT & Intelligence Gathering Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python osint_cli.py -d example.com
  python osint_cli.py -i 8.8.8.8
  python osint_cli.py -e user@example.com
  python osint_cli.py -w https://example.com
  python osint_cli.py -s username
  python osint_cli.py -img https://example.com/image.jpg
  python osint_cli.py -d example.com -o results.json
        """
    )
    
    parser.add_argument('-d', '--domain', help='Gather intelligence on a domain')
    parser.add_argument('-i', '--ip', help='Gather intelligence on an IP address')
    parser.add_argument('-e', '--email', help='Gather intelligence on an email address')
    parser.add_argument('-w', '--web', help='Scrape intelligence from a website URL')
    parser.add_argument('-s', '--social', help='Search for username across social media platforms')
    parser.add_argument('-img', '--image', help='Analyze image metadata and EXIF data')
    parser.add_argument('-o', '--output', help='Save results to JSON file')
    
    args = parser.parse_args()
    
    # Initialize toolkit
    toolkit = OSINTToolkit()
    toolkit.print_banner()
    
    # Check if at least one option is provided
    if not any([args.domain, args.ip, args.email, args.web, args.social, args.image]):
        parser.print_help()
        return
        
    # Run appropriate tool based on arguments
    if args.domain:
        toolkit.run_domain_intel(args.domain, args.output)
    elif args.ip:
        toolkit.run_ip_intel(args.ip, args.output)
    elif args.email:
        toolkit.run_email_intel(args.email, args.output)
    elif args.web:
        toolkit.run_web_scraper(args.web, args.output)
    elif args.social:
        toolkit.run_social_intel(args.social, args.output)
    elif args.image:
        toolkit.run_image_intel(args.image, args.output)

if __name__ == "__main__":
    main()
