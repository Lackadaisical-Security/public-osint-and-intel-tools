"""
Tor Integration Module

Production-grade Tor proxy integration for anonymous OSINT operations.
Provides SOCKS5 proxy configuration and circuit management.
"""

import subprocess
import socket
import time
import requests
from typing import Optional, Dict, Any, Tuple
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TorProxy:
    """Tor SOCKS5 proxy manager for anonymous connections"""
    
    def __init__(self, socks_port: int = 9050, control_port: int = 9051):
        self.socks_port = socks_port
        self.control_port = control_port
        self.tor_process = None
        self.proxies = {
            'http': f'socks5h://127.0.0.1:{socks_port}',
            'https': f'socks5h://127.0.0.1:{socks_port}'
        }
        
    def is_tor_running(self) -> bool:
        """Check if Tor is already running on specified port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', self.socks_port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def start_tor(self, tor_path: str = "tor") -> bool:
        """
        Start Tor daemon
        
        Args:
            tor_path: Path to tor executable
            
        Returns:
            True if started successfully
        """
        if self.is_tor_running():
            logger.info(f"Tor already running on port {self.socks_port}")
            return True
        
        try:
            self.tor_process = subprocess.Popen(
                [tor_path, '--SocksPort', str(self.socks_port)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait for Tor to bootstrap
            logger.info("Waiting for Tor to bootstrap...")
            for i in range(30):
                if self.is_tor_running():
                    logger.info(f"Tor started successfully on port {self.socks_port}")
                    return True
                time.sleep(1)
            
            logger.error("Tor failed to start within timeout")
            return False
            
        except FileNotFoundError:
            logger.error(f"Tor executable not found at: {tor_path}")
            logger.info("Install Tor: apt-get install tor (Debian/Ubuntu) or brew install tor (macOS)")
            return False
        except Exception as e:
            logger.error(f"Failed to start Tor: {e}")
            return False
    
    def stop_tor(self) -> None:
        """Stop Tor daemon if started by this instance"""
        if self.tor_process:
            self.tor_process.terminate()
            self.tor_process.wait()
            logger.info("Tor stopped")
    
    def get_proxies(self) -> Dict[str, str]:
        """Get proxy configuration for requests library"""
        return self.proxies
    
    def test_connection(self) -> Tuple[bool, Optional[str]]:
        """
        Test Tor connection and get exit node IP
        
        Returns:
            (success, ip_address)
        """
        try:
            response = requests.get(
                'https://check.torproject.org/api/ip',
                proxies=self.proxies,
                timeout=10
            )
            data = response.json()
            ip = data.get('IP', 'Unknown')
            is_tor = data.get('IsTor', False)
            
            if is_tor:
                logger.info(f"Tor connection successful. Exit IP: {ip}")
                return True, ip
            else:
                logger.warning(f"Connection not through Tor. IP: {ip}")
                return False, ip
                
        except Exception as e:
            logger.error(f"Tor connection test failed: {e}")
            return False, None
    
    def new_identity(self) -> bool:
        """
        Request new Tor circuit (new exit node)
        
        Note: Requires control port authentication
        Returns True if successful
        """
        try:
            import stem
            import stem.control
            
            with stem.control.Controller.from_port(port=self.control_port) as controller:
                controller.authenticate()
                controller.signal(stem.Signal.NEWNYM)
                logger.info("New Tor circuit requested")
                time.sleep(3)  # Wait for new circuit
                return True
                
        except ImportError:
            logger.warning("stem library not installed. Install: pip install stem")
            logger.info("Circuit renewal not available without stem")
            return False
        except Exception as e:
            logger.error(f"Failed to renew circuit: {e}")
            return False


class TorSession:
    """Requests session pre-configured for Tor"""
    
    def __init__(self, tor_proxy: Optional[TorProxy] = None):
        self.tor_proxy = tor_proxy or TorProxy()
        self.session = requests.Session()
        self.session.proxies.update(self.tor_proxy.get_proxies())
        
        # Security headers
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
    
    def get(self, url: str, **kwargs) -> requests.Response:
        """HTTP GET through Tor"""
        return self.session.get(url, **kwargs)
    
    def post(self, url: str, **kwargs) -> requests.Response:
        """HTTP POST through Tor"""
        return self.session.post(url, **kwargs)
    
    def renew_circuit(self) -> bool:
        """Get new Tor circuit"""
        return self.tor_proxy.new_identity()


def ensure_tor_running() -> TorProxy:
    """
    Ensure Tor is running, start if needed
    
    Returns:
        TorProxy instance
    """
    tor = TorProxy()
    if not tor.is_tor_running():
        tor.start_tor()
    return tor


if __name__ == "__main__":
    # Test Tor integration
    print("Testing Tor integration...")
    
    tor = TorProxy()
    
    if not tor.is_tor_running():
        print("Starting Tor...")
        if not tor.start_tor():
            print("Failed to start Tor. Ensure Tor is installed.")
            exit(1)
    
    # Test connection
    success, ip = tor.test_connection()
    if success:
        print(f"✓ Tor connected successfully")
        print(f"✓ Exit node IP: {ip}")
    else:
        print("✗ Tor connection failed")
        exit(1)
    
    # Test session
    print("\nTesting Tor session...")
    session = TorSession(tor)
    try:
        response = session.get('https://check.torproject.org', timeout=10)
        print(f"✓ HTTP request successful (status: {response.status_code})")
    except Exception as e:
        print(f"✗ HTTP request failed: {e}")
    
    # Cleanup
    tor.stop_tor()
    print("\n✓ Tor integration test complete")
