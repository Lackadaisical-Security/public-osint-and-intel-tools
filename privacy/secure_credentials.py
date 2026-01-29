"""
Secure Credential Storage

Production-grade encrypted credential management for API keys and sensitive data.
Uses Fernet symmetric encryption with key derivation from password.
"""

import os
import json
import getpass
from pathlib import Path
from typing import Dict, Optional, Any
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.backends import default_backend
import base64
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SecureCredentialStore:
    """Encrypted credential storage with password-based key derivation"""
    
    def __init__(self, storage_path: Optional[str] = None):
        self.storage_path = storage_path or os.path.join(
            Path.home(), '.osint_tools', 'credentials.enc'
        )
        self.salt_path = os.path.join(
            Path.home(), '.osint_tools', 'salt.key'
        )
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        
        self._fernet: Optional[Fernet] = None
        self._credentials: Dict[str, Any] = {}
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def _get_or_create_salt(self) -> bytes:
        """Get existing salt or create new one"""
        if os.path.exists(self.salt_path):
            with open(self.salt_path, 'rb') as f:
                return f.read()
        else:
            salt = os.urandom(16)
            with open(self.salt_path, 'wb') as f:
                f.write(salt)
            os.chmod(self.salt_path, 0o600)  # Read/write for owner only
            return salt
    
    def unlock(self, password: Optional[str] = None) -> bool:
        """
        Unlock credential store with password
        
        Args:
            password: Master password. If None, prompts user.
            
        Returns:
            True if successfully unlocked
        """
        if password is None:
            password = getpass.getpass("Enter master password: ")
        
        try:
            salt = self._get_or_create_salt()
            key = self._derive_key(password, salt)
            self._fernet = Fernet(key)
            
            # Load existing credentials if file exists
            if os.path.exists(self.storage_path):
                with open(self.storage_path, 'rb') as f:
                    encrypted_data = f.read()
                    decrypted_data = self._fernet.decrypt(encrypted_data)
                    self._credentials = json.loads(decrypted_data.decode())
                    logger.info(f"Loaded {len(self._credentials)} credentials")
            else:
                self._credentials = {}
                logger.info("Created new credential store")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to unlock credential store: {e}")
            self._fernet = None
            return False
    
    def lock(self) -> None:
        """Lock credential store (clear from memory)"""
        self._fernet = None
        self._credentials = {}
        logger.info("Credential store locked")
    
    def _ensure_unlocked(self) -> None:
        """Ensure store is unlocked before operation"""
        if self._fernet is None:
            raise RuntimeError("Credential store is locked. Call unlock() first.")
    
    def set(self, key: str, value: Any) -> None:
        """
        Store credential
        
        Args:
            key: Credential identifier (e.g., 'SHODAN_API_KEY')
            value: Credential value (string, dict, etc.)
        """
        self._ensure_unlocked()
        self._credentials[key] = value
        logger.info(f"Stored credential: {key}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Retrieve credential
        
        Args:
            key: Credential identifier
            default: Default value if not found
            
        Returns:
            Credential value or default
        """
        self._ensure_unlocked()
        return self._credentials.get(key, default)
    
    def delete(self, key: str) -> bool:
        """
        Delete credential
        
        Args:
            key: Credential identifier
            
        Returns:
            True if deleted, False if not found
        """
        self._ensure_unlocked()
        if key in self._credentials:
            del self._credentials[key]
            logger.info(f"Deleted credential: {key}")
            return True
        return False
    
    def list_keys(self) -> list:
        """List all credential keys"""
        self._ensure_unlocked()
        return list(self._credentials.keys())
    
    def save(self) -> bool:
        """
        Save credentials to encrypted file
        
        Returns:
            True if successful
        """
        self._ensure_unlocked()
        
        try:
            # Serialize and encrypt
            json_data = json.dumps(self._credentials).encode()
            encrypted_data = self._fernet.encrypt(json_data)
            
            # Write atomically (write to temp file, then rename)
            temp_path = self.storage_path + '.tmp'
            with open(temp_path, 'wb') as f:
                f.write(encrypted_data)
            
            os.chmod(temp_path, 0o600)  # Read/write for owner only
            os.rename(temp_path, self.storage_path)
            
            logger.info(f"Saved {len(self._credentials)} credentials to {self.storage_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save credentials: {e}")
            return False
    
    def change_password(self, new_password: Optional[str] = None) -> bool:
        """
        Change master password
        
        Args:
            new_password: New password. If None, prompts user.
            
        Returns:
            True if successful
        """
        self._ensure_unlocked()
        
        if new_password is None:
            new_password = getpass.getpass("Enter new master password: ")
            confirm = getpass.getpass("Confirm new password: ")
            if new_password != confirm:
                logger.error("Passwords do not match")
                return False
        
        try:
            # Generate new salt
            new_salt = os.urandom(16)
            new_key = self._derive_key(new_password, new_salt)
            new_fernet = Fernet(new_key)
            
            # Re-encrypt with new key
            json_data = json.dumps(self._credentials).encode()
            encrypted_data = new_fernet.encrypt(json_data)
            
            # Save new salt and encrypted data
            with open(self.salt_path, 'wb') as f:
                f.write(new_salt)
            
            with open(self.storage_path, 'wb') as f:
                f.write(encrypted_data)
            
            os.chmod(self.salt_path, 0o600)
            os.chmod(self.storage_path, 0o600)
            
            # Update current fernet instance
            self._fernet = new_fernet
            
            logger.info("Master password changed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to change password: {e}")
            return False
    
    def export_env_file(self, output_path: str = ".env") -> bool:
        """
        Export credentials to .env file format
        
        Args:
            output_path: Path to .env file
            
        Returns:
            True if successful
        """
        self._ensure_unlocked()
        
        try:
            with open(output_path, 'w') as f:
                for key, value in self._credentials.items():
                    if isinstance(value, str):
                        f.write(f"{key}={value}\n")
                    else:
                        f.write(f"{key}={json.dumps(value)}\n")
            
            os.chmod(output_path, 0o600)
            logger.info(f"Exported credentials to {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export .env file: {e}")
            return False


class CredentialManager:
    """High-level credential management with environment variable fallback"""
    
    def __init__(self, store: Optional[SecureCredentialStore] = None):
        self.store = store or SecureCredentialStore()
        self._unlocked = False
    
    def get(self, key: str, default: Any = None, from_env: bool = True) -> Any:
        """
        Get credential with fallback to environment variables
        
        Args:
            key: Credential key
            default: Default value
            from_env: Check environment variables if not in store
            
        Returns:
            Credential value
        """
        # Try credential store first
        if self._unlocked:
            value = self.store.get(key)
            if value is not None:
                return value
        
        # Fall back to environment variable
        if from_env:
            value = os.environ.get(key)
            if value is not None:
                return value
        
        return default
    
    def unlock(self, password: Optional[str] = None) -> bool:
        """Unlock credential store"""
        if self.store.unlock(password):
            self._unlocked = True
            return True
        return False
    
    def set(self, key: str, value: Any, save: bool = True) -> None:
        """Set credential and optionally save"""
        if not self._unlocked:
            if not self.unlock():
                raise RuntimeError("Failed to unlock credential store")
        
        self.store.set(key, value)
        if save:
            self.store.save()


if __name__ == "__main__":
    # Test secure credential storage
    print("Testing secure credential storage...")
    
    # Create store
    import tempfile
    temp_dir = tempfile.mkdtemp()
    store_path = os.path.join(temp_dir, "test_creds.enc")
    
    store = SecureCredentialStore(store_path)
    
    # Test unlock with password
    print("\n1. Unlocking store with password...")
    if store.unlock("test_password_123"):
        print("  ✓ Store unlocked")
    
    # Test storing credentials
    print("\n2. Storing credentials...")
    store.set("SHODAN_API_KEY", "test_shodan_key_12345")
    store.set("VIRUSTOTAL_API_KEY", "test_vt_key_67890")
    store.set("DATABASE_CONFIG", {"host": "localhost", "port": 5432})
    print(f"  ✓ Stored {len(store.list_keys())} credentials")
    
    # Test saving
    print("\n3. Saving to encrypted file...")
    if store.save():
        print(f"  ✓ Saved to {store_path}")
    
    # Test locking and unlocking
    print("\n4. Locking and unlocking...")
    store.lock()
    print("  ✓ Store locked")
    
    if store.unlock("test_password_123"):
        print("  ✓ Store unlocked again")
        print(f"  ✓ Loaded {len(store.list_keys())} credentials")
    
    # Test retrieval
    print("\n5. Retrieving credentials...")
    shodan_key = store.get("SHODAN_API_KEY")
    print(f"  SHODAN_API_KEY: {shodan_key}")
    
    # Clean up
    import shutil
    shutil.rmtree(temp_dir)
    
    print("\n✓ Secure credential storage test complete")
