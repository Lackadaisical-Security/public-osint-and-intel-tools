"""
Proxy Rotation System

Production-grade proxy rotation for OSINT operations.
Supports SOCKS5, HTTP/HTTPS proxies with health checking and automatic failover.
"""

import requests
import time
import random
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
import concurrent.futures

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ProxyInfo:
    """Proxy configuration and metadata"""
    protocol: str  # 'http', 'https', 'socks5'
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    last_used: Optional[datetime] = None
    failures: int = 0
    latency: Optional[float] = None
    is_alive: bool = True
    
    def get_url(self) -> str:
        """Get proxy URL"""
        if self.username and self.password:
            return f"{self.protocol}://{self.username}:{self.password}@{self.host}:{self.port}"
        return f"{self.protocol}://{self.host}:{self.port}"
    
    def get_proxies_dict(self) -> Dict[str, str]:
        """Get proxies dictionary for requests"""
        url = self.get_url()
        return {'http': url, 'https': url}


class ProxyRotator:
    """Intelligent proxy rotation with health checking"""
    
    def __init__(self, max_failures: int = 3, cooldown_seconds: int = 300):
        self.proxies: List[ProxyInfo] = []
        self.max_failures = max_failures
        self.cooldown_seconds = cooldown_seconds
        self.current_index = 0
        
    def add_proxy(self, protocol: str, host: str, port: int, 
                  username: Optional[str] = None, password: Optional[str] = None) -> None:
        """Add proxy to rotation pool"""
        proxy = ProxyInfo(
            protocol=protocol,
            host=host,
            port=port,
            username=username,
            password=password
        )
        self.proxies.append(proxy)
        logger.info(f"Added proxy: {protocol}://{host}:{port}")
    
    def load_from_file(self, filepath: str, protocol: str = "http") -> int:
        """
        Load proxies from file (one per line: host:port or host:port:user:pass)
        
        Returns:
            Number of proxies loaded
        """
        count = 0
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    parts = line.split(':')
                    if len(parts) >= 2:
                        host = parts[0]
                        port = int(parts[1])
                        username = parts[2] if len(parts) > 2 else None
                        password = parts[3] if len(parts) > 3 else None
                        self.add_proxy(protocol, host, port, username, password)
                        count += 1
            
            logger.info(f"Loaded {count} proxies from {filepath}")
            return count
        except Exception as e:
            logger.error(f"Failed to load proxies: {e}")
            return 0
    
    def test_proxy(self, proxy: ProxyInfo, test_url: str = "https://httpbin.org/ip", 
                   timeout: int = 10) -> Tuple[bool, Optional[float]]:
        """
        Test if proxy is working
        
        Returns:
            (is_working, latency_ms)
        """
        try:
            start = time.time()
            response = requests.get(
                test_url,
                proxies=proxy.get_proxies_dict(),
                timeout=timeout
            )
            latency = (time.time() - start) * 1000
            
            if response.status_code == 200:
                return True, latency
            return False, None
            
        except Exception as e:
            logger.debug(f"Proxy test failed for {proxy.host}:{proxy.port}: {e}")
            return False, None
    
    def health_check(self, test_url: str = "https://httpbin.org/ip", 
                     max_workers: int = 10) -> Dict[str, int]:
        """
        Check health of all proxies in parallel
        
        Returns:
            Statistics dict
        """
        logger.info(f"Testing {len(self.proxies)} proxies...")
        stats = {'alive': 0, 'dead': 0, 'total': len(self.proxies)}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_proxy = {
                executor.submit(self.test_proxy, proxy, test_url): proxy 
                for proxy in self.proxies
            }
            
            for future in concurrent.futures.as_completed(future_to_proxy):
                proxy = future_to_proxy[future]
                try:
                    is_alive, latency = future.result()
                    proxy.is_alive = is_alive
                    proxy.latency = latency
                    
                    if is_alive:
                        stats['alive'] += 1
                        logger.info(f"✓ {proxy.host}:{proxy.port} - {latency:.0f}ms")
                    else:
                        stats['dead'] += 1
                        logger.warning(f"✗ {proxy.host}:{proxy.port} - Dead")
                        
                except Exception as e:
                    logger.error(f"Health check failed for {proxy.host}: {e}")
                    stats['dead'] += 1
        
        logger.info(f"Health check complete: {stats['alive']}/{stats['total']} proxies alive")
        return stats
    
    def get_next_proxy(self, strategy: str = "round-robin") -> Optional[ProxyInfo]:
        """
        Get next proxy using specified strategy
        
        Strategies:
            - round-robin: Sequential rotation
            - random: Random selection
            - fastest: Lowest latency
            - least-used: Proxy used longest time ago
        """
        alive_proxies = [p for p in self.proxies if p.is_alive and p.failures < self.max_failures]
        
        if not alive_proxies:
            logger.error("No alive proxies available")
            return None
        
        if strategy == "round-robin":
            self.current_index = (self.current_index + 1) % len(alive_proxies)
            proxy = alive_proxies[self.current_index]
            
        elif strategy == "random":
            proxy = random.choice(alive_proxies)
            
        elif strategy == "fastest":
            # Sort by latency, None values go to end
            sorted_proxies = sorted(
                alive_proxies, 
                key=lambda p: p.latency if p.latency is not None else float('inf')
            )
            proxy = sorted_proxies[0]
            
        elif strategy == "least-used":
            # Sort by last_used, None (never used) first
            sorted_proxies = sorted(
                alive_proxies,
                key=lambda p: p.last_used if p.last_used else datetime.min
            )
            proxy = sorted_proxies[0]
        else:
            logger.warning(f"Unknown strategy '{strategy}', using round-robin")
            return self.get_next_proxy("round-robin")
        
        proxy.last_used = datetime.now()
        return proxy
    
    def mark_failure(self, proxy: ProxyInfo) -> None:
        """Mark proxy as failed"""
        proxy.failures += 1
        logger.warning(f"Proxy failure {proxy.failures}/{self.max_failures}: {proxy.host}:{proxy.port}")
        
        if proxy.failures >= self.max_failures:
            proxy.is_alive = False
            logger.error(f"Proxy marked dead: {proxy.host}:{proxy.port}")
    
    def mark_success(self, proxy: ProxyInfo) -> None:
        """Mark proxy as successful (reset failure count)"""
        if proxy.failures > 0:
            logger.info(f"Proxy recovered: {proxy.host}:{proxy.port}")
        proxy.failures = 0
    
    def get_stats(self) -> Dict[str, any]:
        """Get proxy pool statistics"""
        alive = [p for p in self.proxies if p.is_alive]
        dead = [p for p in self.proxies if not p.is_alive]
        
        avg_latency = None
        if alive:
            latencies = [p.latency for p in alive if p.latency is not None]
            if latencies:
                avg_latency = sum(latencies) / len(latencies)
        
        return {
            'total': len(self.proxies),
            'alive': len(alive),
            'dead': len(dead),
            'avg_latency_ms': round(avg_latency, 2) if avg_latency else None,
            'strategies': ['round-robin', 'random', 'fastest', 'least-used']
        }


class ProxySession:
    """Requests session with automatic proxy rotation"""
    
    def __init__(self, rotator: ProxyRotator, strategy: str = "round-robin", 
                 max_retries: int = 3):
        self.rotator = rotator
        self.strategy = strategy
        self.max_retries = max_retries
        self.session = requests.Session()
    
    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make request with automatic proxy rotation and retry"""
        for attempt in range(self.max_retries):
            proxy = self.rotator.get_next_proxy(self.strategy)
            if not proxy:
                raise Exception("No proxies available")
            
            try:
                self.session.proxies.update(proxy.get_proxies_dict())
                response = self.session.request(method, url, **kwargs)
                self.rotator.mark_success(proxy)
                return response
                
            except Exception as e:
                logger.warning(f"Request failed (attempt {attempt + 1}/{self.max_retries}): {e}")
                self.rotator.mark_failure(proxy)
                
                if attempt == self.max_retries - 1:
                    raise
                time.sleep(1)
        
        raise Exception("All retry attempts failed")
    
    def get(self, url: str, **kwargs) -> requests.Response:
        """HTTP GET with proxy rotation"""
        return self.request('GET', url, **kwargs)
    
    def post(self, url: str, **kwargs) -> requests.Response:
        """HTTP POST with proxy rotation"""
        return self.request('POST', url, **kwargs)


if __name__ == "__main__":
    # Test proxy rotation
    print("Testing proxy rotation system...")
    
    rotator = ProxyRotator()
    
    # Add some public test proxies (these may not work - for demonstration)
    rotator.add_proxy("http", "httpbin.org", 80)  # Direct connection for testing
    
    # Run health check
    stats = rotator.health_check()
    print(f"\nProxy stats: {stats}")
    
    # Get proxy statistics
    print(f"\nRotator stats: {rotator.get_stats()}")
    
    print("\n✓ Proxy rotation system test complete")
