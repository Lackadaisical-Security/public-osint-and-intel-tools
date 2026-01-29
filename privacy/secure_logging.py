"""
Secure Logging Module

Production-grade audit logging for OSINT operations with encryption and sanitization.
Logs operations while protecting sensitive data and maintaining OPSEC.
"""

import logging
import json
import os
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
from cryptography.fernet import Fernet
import re


class SanitizingFormatter(logging.Formatter):
    """Log formatter that sanitizes sensitive data"""
    
    # Patterns to sanitize
    PATTERNS = {
        'email': (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL_REDACTED]'),
        'ip': (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[IP_REDACTED]'),
        'phone': (r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '[PHONE_REDACTED]'),
        'api_key': (r'\b[A-Za-z0-9]{32,}\b', '[API_KEY_REDACTED]'),
        'ssn': (r'\b\d{3}-\d{2}-\d{4}\b', '[SSN_REDACTED]'),
        'credit_card': (r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', '[CC_REDACTED]'),
    }
    
    def format(self, record):
        """Format log record with sanitization"""
        # Get original message
        original = super().format(record)
        
        # Apply all sanitization patterns
        sanitized = original
        for pattern, replacement in self.PATTERNS.values():
            sanitized = re.sub(pattern, replacement, sanitized)
        
        return sanitized


class AuditLogger:
    """Secure audit logger for OSINT operations"""
    
    def __init__(self, log_dir: Optional[str] = None, encrypt: bool = True):
        self.log_dir = log_dir or os.path.join(Path.home(), '.osint_tools', 'logs')
        self.encrypt = encrypt
        self.session_id = hashlib.sha256(
            f"{datetime.now().isoformat()}{os.getpid()}".encode()
        ).hexdigest()[:16]
        
        # Create log directory
        os.makedirs(self.log_dir, exist_ok=True)
        os.chmod(self.log_dir, 0o700)  # Owner only
        
        # Setup logging
        self.logger = self._setup_logger()
        
        # Encryption key
        self.fernet = None
        if encrypt:
            self._setup_encryption()
    
    def _setup_logger(self) -> logging.Logger:
        """Configure logger with sanitizing formatter"""
        logger = logging.getLogger(f'osint_audit_{self.session_id}')
        logger.setLevel(logging.INFO)
        logger.handlers = []  # Clear existing handlers
        
        # File handler with sanitization
        log_file = os.path.join(
            self.log_dir,
            f"audit_{datetime.now().strftime('%Y%m%d')}_{self.session_id}.log"
        )
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        
        # Use sanitizing formatter
        formatter = SanitizingFormatter(
            '%(asctime)s | %(levelname)s | %(session_id)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        # Set file permissions
        os.chmod(log_file, 0o600)  # Owner read/write only
        
        return logger
    
    def _setup_encryption(self) -> None:
        """Setup encryption for sensitive log entries"""
        key_file = os.path.join(self.log_dir, '.log_key')
        
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                key = f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            os.chmod(key_file, 0o600)
        
        self.fernet = Fernet(key)
    
    def log_operation(self, operation: str, target: str, details: Optional[Dict[str, Any]] = None) -> None:
        """
        Log an OSINT operation
        
        Args:
            operation: Type of operation (e.g., 'domain_lookup', 'port_scan')
            target: Target of operation (domain, IP, etc.)
            details: Additional operation details
        """
        log_entry = {
            'session_id': self.session_id,
            'timestamp': datetime.now().isoformat(),
            'operation': operation,
            'target': target,
            'details': details or {}
        }
        
        self.logger.info(
            json.dumps(log_entry),
            extra={'session_id': self.session_id}
        )
    
    def log_success(self, operation: str, target: str, result_summary: str) -> None:
        """Log successful operation"""
        self.log_operation(
            operation,
            target,
            {'status': 'success', 'result': result_summary}
        )
    
    def log_failure(self, operation: str, target: str, error: str) -> None:
        """Log failed operation"""
        self.log_operation(
            operation,
            target,
            {'status': 'failure', 'error': str(error)}
        )
    
    def log_sensitive(self, message: str, data: Dict[str, Any]) -> None:
        """
        Log sensitive data with encryption
        
        Args:
            message: Log message
            data: Sensitive data to encrypt
        """
        if self.fernet:
            # Encrypt sensitive data
            encrypted = self.fernet.encrypt(json.dumps(data).encode())
            self.logger.info(
                f"{message} | ENCRYPTED_DATA: {encrypted.decode()}",
                extra={'session_id': self.session_id}
            )
        else:
            # Fall back to regular logging with sanitization
            self.logger.info(
                f"{message} | DATA: {json.dumps(data)}",
                extra={'session_id': self.session_id}
            )
    
    def log_auth_attempt(self, service: str, success: bool, username: Optional[str] = None) -> None:
        """Log authentication attempt"""
        self.log_operation(
            'authentication',
            service,
            {
                'status': 'success' if success else 'failure',
                'username': username or '[REDACTED]'
            }
        )
    
    def log_api_call(self, api: str, endpoint: str, status_code: int) -> None:
        """Log API call"""
        self.log_operation(
            'api_call',
            api,
            {
                'endpoint': endpoint,
                'status_code': status_code
            }
        )
    
    def get_session_id(self) -> str:
        """Get current session ID"""
        return self.session_id
    
    def export_session_log(self, output_file: str) -> bool:
        """
        Export session log to file
        
        Args:
            output_file: Path to output file
            
        Returns:
            True if successful
        """
        try:
            # Find all log files for this session
            log_files = [
                f for f in os.listdir(self.log_dir)
                if self.session_id in f and f.endswith('.log')
            ]
            
            if not log_files:
                return False
            
            # Combine logs
            with open(output_file, 'w') as out:
                for log_file in log_files:
                    with open(os.path.join(self.log_dir, log_file), 'r') as f:
                        out.write(f.read())
            
            return True
        except Exception:
            return False


class OPSECLogger:
    """OPSEC-focused logger with minimal data retention"""
    
    def __init__(self):
        self.events = []
        self.max_events = 100  # Keep only last 100 events in memory
    
    def log_event(self, event_type: str, details: str) -> None:
        """Log event to memory (not disk)"""
        self.events.append({
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'details': details
        })
        
        # Trim old events
        if len(self.events) > self.max_events:
            self.events = self.events[-self.max_events:]
    
    def get_events(self) -> list:
        """Get recent events"""
        return self.events.copy()
    
    def clear(self) -> None:
        """Clear all events from memory"""
        self.events = []
    
    def log_opsec_violation(self, violation: str, severity: str) -> None:
        """Log OPSEC violation"""
        self.log_event('opsec_violation', f"[{severity}] {violation}")


if __name__ == "__main__":
    # Test audit logging
    print("Testing secure audit logging...")
    
    import tempfile
    temp_dir = tempfile.mkdtemp()
    
    # Create audit logger
    logger = AuditLogger(log_dir=temp_dir)
    
    print(f"\n1. Session ID: {logger.get_session_id()}")
    
    # Log various operations
    print("\n2. Logging operations...")
    logger.log_operation('domain_lookup', 'example.com', {'records': 5})
    logger.log_success('port_scan', '192.168.1.1', 'Found 3 open ports')
    logger.log_failure('whois_lookup', 'invalid.domain', 'Timeout')
    
    # Log API call
    logger.log_api_call('Shodan', '/search', 200)
    
    # Log sensitive data (will be encrypted)
    logger.log_sensitive('API credentials used', {
        'api_key': 'super_secret_key_12345',
        'email': 'test@example.com'
    })
    
    # Export session log
    export_path = os.path.join(temp_dir, 'session_export.log')
    if logger.export_session_log(export_path):
        print(f"\n3. Exported session log to: {export_path}")
        
        # Show sanitized content
        with open(export_path, 'r') as f:
            content = f.read()
            print(f"\n4. Log content (first 500 chars):")
            print(content[:500])
    
    # Test OPSEC logger
    print("\n5. Testing OPSEC logger...")
    opsec = OPSECLogger()
    opsec.log_event('tool_start', 'Started domain reconnaissance')
    opsec.log_opsec_violation('DNS leak detected', 'HIGH')
    
    print(f"   Logged events: {len(opsec.get_events())}")
    
    # Cleanup
    import shutil
    shutil.rmtree(temp_dir)
    
    print("\n✓ Secure audit logging test complete")
