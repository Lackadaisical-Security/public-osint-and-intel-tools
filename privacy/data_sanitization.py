"""
Data Sanitization Utilities

Production-grade PII detection, redaction, and data sanitization for OSINT results.
"""

import re
from typing import Dict, List, Any, Callable, Optional, Set
import hashlib
import json


class PIIDetector:
    """Detect personally identifiable information in text"""
    
    # Regex patterns for various PII types
    PATTERNS = {
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'phone_us': r'\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b',
        'phone_intl': r'\+[0-9]{1,3}[-.\s]?[0-9]{1,14}',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'credit_card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
        'ip_address': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
        'mac_address': r'\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b',
        'passport': r'\b[A-Z]{1,2}[0-9]{6,9}\b',
        'url': r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)',
        'bitcoin': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
        'ethereum': r'\b0x[a-fA-F0-9]{40}\b',
    }
    
    @classmethod
    def detect(cls, text: str, pii_types: Optional[List[str]] = None) -> Dict[str, List[str]]:
        """
        Detect PII in text
        
        Args:
            text: Text to scan
            pii_types: List of PII types to detect (None = all)
            
        Returns:
            Dictionary mapping PII type to list of found instances
        """
        results = {}
        
        patterns = cls.PATTERNS if pii_types is None else {
            k: v for k, v in cls.PATTERNS.items() if k in pii_types
        }
        
        for pii_type, pattern in patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                # Handle tuples from grouped patterns
                if isinstance(matches[0], tuple):
                    matches = [''.join(m) for m in matches]
                results[pii_type] = matches
        
        return results
    
    @classmethod
    def has_pii(cls, text: str, pii_types: Optional[List[str]] = None) -> bool:
        """Check if text contains any PII"""
        detected = cls.detect(text, pii_types)
        return len(detected) > 0
    
    @classmethod
    def count_pii(cls, text: str) -> Dict[str, int]:
        """Count PII instances by type"""
        detected = cls.detect(text)
        return {k: len(v) for k, v in detected.items()}


class DataSanitizer:
    """Sanitize data by removing or masking PII"""
    
    @staticmethod
    def redact(text: str, pii_types: Optional[List[str]] = None, 
               placeholder: str = '[REDACTED]') -> str:
        """
        Redact PII from text
        
        Args:
            text: Text to sanitize
            pii_types: Types to redact (None = all)
            placeholder: Replacement text
            
        Returns:
            Sanitized text
        """
        patterns = PIIDetector.PATTERNS if pii_types is None else {
            k: v for k, v in PIIDetector.PATTERNS.items() if k in pii_types
        }
        
        sanitized = text
        for pii_type, pattern in patterns.items():
            custom_placeholder = f"[{pii_type.upper()}_REDACTED]"
            sanitized = re.sub(pattern, custom_placeholder, sanitized)
        
        return sanitized
    
    @staticmethod
    def mask(text: str, mask_char: str = '*', show_chars: int = 4) -> str:
        """
        Mask sensitive data while showing partial information
        
        Args:
            text: Text to mask
            mask_char: Character to use for masking
            show_chars: Number of characters to show at end
            
        Returns:
            Masked text
        """
        if len(text) <= show_chars:
            return mask_char * len(text)
        
        masked_length = len(text) - show_chars
        return (mask_char * masked_length) + text[-show_chars:]
    
    @staticmethod
    def hash_pii(text: str, salt: str = "") -> str:
        """
        Hash PII for pseudonymization
        
        Args:
            text: Text to hash
            salt: Optional salt for hashing
            
        Returns:
            Hashed value
        """
        return hashlib.sha256(f"{text}{salt}".encode()).hexdigest()
    
    @staticmethod
    def sanitize_email(email: str, method: str = 'mask') -> str:
        """
        Sanitize email address
        
        Args:
            email: Email to sanitize
            method: 'mask', 'redact', or 'hash'
            
        Returns:
            Sanitized email
        """
        if method == 'redact':
            return '[EMAIL_REDACTED]'
        elif method == 'hash':
            return DataSanitizer.hash_pii(email)
        else:  # mask
            if '@' in email:
                local, domain = email.split('@', 1)
                masked_local = DataSanitizer.mask(local, show_chars=1)
                return f"{masked_local}@{domain}"
            return DataSanitizer.mask(email)
    
    @staticmethod
    def sanitize_phone(phone: str, method: str = 'mask') -> str:
        """Sanitize phone number"""
        if method == 'redact':
            return '[PHONE_REDACTED]'
        elif method == 'hash':
            return DataSanitizer.hash_pii(phone)
        else:  # mask
            digits = re.sub(r'\D', '', phone)
            if len(digits) >= 4:
                return f"***-***-{digits[-4:]}"
            return '***-****'
    
    @staticmethod
    def sanitize_ip(ip: str, method: str = 'partial') -> str:
        """
        Sanitize IP address
        
        Args:
            ip: IP address
            method: 'partial' (hide last octet), 'redact', or 'hash'
        """
        if method == 'redact':
            return '[IP_REDACTED]'
        elif method == 'hash':
            return DataSanitizer.hash_pii(ip)
        else:  # partial
            parts = ip.split('.')
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.XXX"
            return ip
    
    @staticmethod
    def sanitize_dict(data: Dict[str, Any], 
                     sensitive_keys: Optional[Set[str]] = None) -> Dict[str, Any]:
        """
        Sanitize dictionary by removing/masking sensitive keys
        
        Args:
            data: Dictionary to sanitize
            sensitive_keys: Keys to sanitize (default: common sensitive keys)
            
        Returns:
            Sanitized dictionary
        """
        if sensitive_keys is None:
            sensitive_keys = {
                'password', 'passwd', 'pwd',
                'api_key', 'apikey', 'key',
                'secret', 'token', 'auth',
                'email', 'phone', 'ssn',
                'credit_card', 'cc_number',
                'address', 'location'
            }
        
        sanitized = {}
        for key, value in data.items():
            key_lower = key.lower()
            
            # Check if key is sensitive
            is_sensitive = any(sk in key_lower for sk in sensitive_keys)
            
            if is_sensitive:
                if isinstance(value, str):
                    sanitized[key] = DataSanitizer.mask(value)
                else:
                    sanitized[key] = '[REDACTED]'
            elif isinstance(value, dict):
                # Recursively sanitize nested dicts
                sanitized[key] = DataSanitizer.sanitize_dict(value, sensitive_keys)
            elif isinstance(value, list):
                # Sanitize list items
                sanitized[key] = [
                    DataSanitizer.sanitize_dict(item, sensitive_keys) 
                    if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                sanitized[key] = value
        
        return sanitized


class DataMinimizer:
    """Minimize data collection and retention"""
    
    @staticmethod
    def remove_metadata(data: Dict[str, Any], 
                       keep_fields: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Remove all fields except those explicitly kept
        
        Args:
            data: Data dictionary
            keep_fields: Fields to keep (whitelist)
            
        Returns:
            Minimized data
        """
        if keep_fields is None:
            return {}
        
        return {k: v for k, v in data.items() if k in keep_fields}
    
    @staticmethod
    def aggregate_data(records: List[Dict[str, Any]], 
                      aggregate_by: str) -> Dict[str, int]:
        """
        Aggregate records to remove individual-level data
        
        Args:
            records: List of records
            aggregate_by: Field to aggregate by
            
        Returns:
            Aggregated counts
        """
        aggregated = {}
        for record in records:
            key = record.get(aggregate_by, 'unknown')
            aggregated[key] = aggregated.get(key, 0) + 1
        
        return aggregated
    
    @staticmethod
    def anonymize_timestamps(timestamp: str, 
                           precision: str = 'day') -> str:
        """
        Reduce timestamp precision for anonymization
        
        Args:
            timestamp: ISO format timestamp
            precision: 'year', 'month', 'day', 'hour'
            
        Returns:
            Anonymized timestamp
        """
        from datetime import datetime
        
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        
        if precision == 'year':
            return dt.strftime('%Y')
        elif precision == 'month':
            return dt.strftime('%Y-%m')
        elif precision == 'day':
            return dt.strftime('%Y-%m-%d')
        elif precision == 'hour':
            return dt.strftime('%Y-%m-%d %H:00')
        else:
            return timestamp


if __name__ == "__main__":
    # Test data sanitization
    print("Testing data sanitization utilities...\n")
    
    # Test PII detection
    print("1. PII Detection:")
    test_text = """
    Contact: john.doe@example.com
    Phone: 555-123-4567
    SSN: 123-45-6789
    IP: 192.168.1.100
    """
    
    detected = PIIDetector.detect(test_text)
    for pii_type, instances in detected.items():
        print(f"   {pii_type}: {instances}")
    
    # Test redaction
    print("\n2. Text Redaction:")
    redacted = DataSanitizer.redact(test_text)
    print(redacted)
    
    # Test email sanitization
    print("\n3. Email Sanitization:")
    email = "john.doe@example.com"
    print(f"   Original: {email}")
    print(f"   Masked: {DataSanitizer.sanitize_email(email, 'mask')}")
    print(f"   Hashed: {DataSanitizer.sanitize_email(email, 'hash')[:32]}...")
    
    # Test dict sanitization
    print("\n4. Dictionary Sanitization:")
    data = {
        'domain': 'example.com',
        'email': 'admin@example.com',
        'api_key': 'super_secret_key_12345',
        'records': 5
    }
    print(f"   Original: {data}")
    sanitized = DataSanitizer.sanitize_dict(data)
    print(f"   Sanitized: {sanitized}")
    
    # Test data minimization
    print("\n5. Data Minimization:")
    full_data = {
        'domain': 'example.com',
        'email': 'admin@example.com',
        'ip': '192.168.1.1',
        'records': 5,
        'timestamp': '2024-01-15T10:30:00'
    }
    minimized = DataMinimizer.remove_metadata(full_data, keep_fields=['domain', 'records'])
    print(f"   Original fields: {list(full_data.keys())}")
    print(f"   Minimized: {minimized}")
    
    print("\n✓ Data sanitization test complete")
