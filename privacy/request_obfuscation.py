"""
Request Obfuscation Module

Production-grade HTTP request obfuscation for OSINT operations.
Implements browser fingerprint randomization, header manipulation, and anti-detection.
"""

import random
import hashlib
import time
from typing import Dict, List, Optional
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class UserAgentRotator:
    """Realistic user agent rotation"""
    
    # Real-world user agents (current as of 2024-2026)
    USER_AGENTS = {
        'chrome_windows': [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        ],
        'firefox_windows': [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
        ],
        'chrome_mac': [
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        ],
        'safari_mac': [
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
        ],
        'chrome_linux': [
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        ],
        'firefox_linux': [
            'Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0',
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0',
        ],
    }
    
    @classmethod
    def get_random(cls, browser: Optional[str] = None) -> str:
        """
        Get random user agent
        
        Args:
            browser: Specific browser family or None for random
        """
        if browser and browser in cls.USER_AGENTS:
            return random.choice(cls.USER_AGENTS[browser])
        
        all_agents = [ua for uas in cls.USER_AGENTS.values() for ua in uas]
        return random.choice(all_agents)
    
    @classmethod
    def get_matching_headers(cls, user_agent: str) -> Dict[str, str]:
        """Get headers that match the user agent"""
        headers = {
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Chrome-specific headers
        if 'Chrome' in user_agent:
            headers.update({
                'sec-ch-ua': '"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"' if 'Windows' in user_agent else '"Linux"',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-User': '?1',
                'Sec-Fetch-Dest': 'document',
            })
        
        # Firefox-specific headers
        if 'Firefox' in user_agent:
            headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        
        return headers


class HeaderObfuscator:
    """HTTP header obfuscation and randomization"""
    
    ACCEPT_LANGUAGES = [
        'en-US,en;q=0.9',
        'en-GB,en;q=0.9',
        'en-US,en;q=0.5',
        'en-CA,en;q=0.9',
    ]
    
    ACCEPT_ENCODINGS = [
        'gzip, deflate, br',
        'gzip, deflate',
    ]
    
    REFERERS = [
        'https://www.google.com/',
        'https://www.bing.com/',
        'https://duckduckgo.com/',
        None,  # No referer
    ]
    
    @classmethod
    def randomize_headers(cls, base_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """
        Generate randomized but realistic HTTP headers
        
        Args:
            base_headers: Optional base headers to extend
        """
        headers = base_headers.copy() if base_headers else {}
        
        # Random user agent if not provided
        if 'User-Agent' not in headers:
            ua = UserAgentRotator.get_random()
            headers.update(UserAgentRotator.get_matching_headers(ua))
        
        # Randomize optional headers
        headers['Accept-Language'] = random.choice(cls.ACCEPT_LANGUAGES)
        headers['Accept-Encoding'] = random.choice(cls.ACCEPT_ENCODINGS)
        
        # Random referer (or none)
        referer = random.choice(cls.REFERERS)
        if referer:
            headers['Referer'] = referer
        
        # Random cache control
        if random.random() > 0.5:
            headers['Cache-Control'] = random.choice(['no-cache', 'max-age=0'])
        
        return headers
    
    @classmethod
    def spoof_referer(cls, target_domain: str) -> str:
        """Generate believable referer for target domain"""
        options = [
            f'https://www.google.com/search?q={target_domain}',
            f'https://www.bing.com/search?q={target_domain}',
            f'https://{target_domain}/',
            'https://www.reddit.com/',
            'https://news.ycombinator.com/',
        ]
        return random.choice(options)


class FingerprintRandomizer:
    """Browser fingerprint randomization"""
    
    SCREEN_RESOLUTIONS = [
        '1920x1080',
        '1366x768',
        '1536x864',
        '1440x900',
        '2560x1440',
    ]
    
    COLOR_DEPTHS = [24, 32]
    
    TIMEZONES = [
        'America/New_York',
        'America/Chicago',
        'America/Los_Angeles',
        'Europe/London',
        'Europe/Paris',
    ]
    
    @classmethod
    def generate_fingerprint(cls) -> Dict[str, any]:
        """Generate randomized browser fingerprint"""
        return {
            'screen_resolution': random.choice(cls.SCREEN_RESOLUTIONS),
            'color_depth': random.choice(cls.COLOR_DEPTHS),
            'timezone': random.choice(cls.TIMEZONES),
            'platform': random.choice(['Win32', 'MacIntel', 'Linux x86_64']),
            'hardware_concurrency': random.choice([2, 4, 8, 16]),
            'device_memory': random.choice([4, 8, 16]),
            'do_not_track': random.choice(['1', None]),
        }


class RateLimiter:
    """Intelligent rate limiting to avoid detection"""
    
    def __init__(self, min_delay: float = 1.0, max_delay: float = 3.0, 
                 requests_per_minute: int = 20):
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.requests_per_minute = requests_per_minute
        self.request_times: List[float] = []
        
    def wait(self) -> None:
        """Wait appropriate amount before next request"""
        now = time.time()
        
        # Remove requests older than 1 minute
        self.request_times = [t for t in self.request_times if now - t < 60]
        
        # Check if we're at rate limit
        if len(self.request_times) >= self.requests_per_minute:
            oldest = self.request_times[0]
            wait_time = 60 - (now - oldest)
            if wait_time > 0:
                logger.info(f"Rate limit reached, waiting {wait_time:.1f}s")
                time.sleep(wait_time)
                now = time.time()
        
        # Random delay between min and max
        delay = random.uniform(self.min_delay, self.max_delay)
        time.sleep(delay)
        
        self.request_times.append(now)
    
    def get_stats(self) -> Dict[str, any]:
        """Get rate limiting statistics"""
        now = time.time()
        recent = [t for t in self.request_times if now - t < 60]
        
        return {
            'requests_last_minute': len(recent),
            'limit': self.requests_per_minute,
            'min_delay': self.min_delay,
            'max_delay': self.max_delay,
        }


class ObfuscatedSession:
    """HTTP session with comprehensive obfuscation"""
    
    def __init__(self, min_delay: float = 1.0, max_delay: float = 3.0,
                 requests_per_minute: int = 20):
        import requests
        
        self.session = requests.Session()
        self.rate_limiter = RateLimiter(min_delay, max_delay, requests_per_minute)
        self.user_agent = UserAgentRotator.get_random()
        self.fingerprint = FingerprintRandomizer.generate_fingerprint()
        
        # Set initial headers
        self._update_headers()
    
    def _update_headers(self) -> None:
        """Update session headers with obfuscation"""
        headers = UserAgentRotator.get_matching_headers(self.user_agent)
        headers = HeaderObfuscator.randomize_headers(headers)
        self.session.headers.update(headers)
    
    def rotate_identity(self) -> None:
        """Rotate user agent and fingerprint"""
        self.user_agent = UserAgentRotator.get_random()
        self.fingerprint = FingerprintRandomizer.generate_fingerprint()
        self._update_headers()
        logger.info("Rotated browser identity")
    
    def request(self, method: str, url: str, **kwargs) -> any:
        """Make obfuscated HTTP request"""
        self.rate_limiter.wait()
        
        # Merge custom headers with session headers
        if 'headers' in kwargs:
            headers = HeaderObfuscator.randomize_headers(kwargs['headers'])
            kwargs['headers'] = headers
        
        return self.session.request(method, url, **kwargs)
    
    def get(self, url: str, **kwargs) -> any:
        """HTTP GET with obfuscation"""
        return self.request('GET', url, **kwargs)
    
    def post(self, url: str, **kwargs) -> any:
        """HTTP POST with obfuscation"""
        return self.request('POST', url, **kwargs)


if __name__ == "__main__":
    # Test obfuscation
    print("Testing request obfuscation...")
    
    # Test user agent rotation
    print("\n1. User Agent Rotation:")
    for i in range(3):
        ua = UserAgentRotator.get_random()
        print(f"  {i+1}. {ua[:80]}...")
    
    # Test header obfuscation
    print("\n2. Header Obfuscation:")
    headers = HeaderObfuscator.randomize_headers()
    for k, v in list(headers.items())[:5]:
        print(f"  {k}: {v}")
    
    # Test fingerprint randomization
    print("\n3. Browser Fingerprint:")
    fp = FingerprintRandomizer.generate_fingerprint()
    for k, v in fp.items():
        print(f"  {k}: {v}")
    
    # Test rate limiter
    print("\n4. Rate Limiter:")
    limiter = RateLimiter(min_delay=0.1, max_delay=0.2, requests_per_minute=5)
    print(f"  Stats: {limiter.get_stats()}")
    
    print("\n✓ Request obfuscation test complete")
