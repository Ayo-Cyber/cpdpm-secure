"""
CPDPM Hybrid Encryption Module

This module implements the hybrid encryption approach of CPDPM,
combining polynomial transformations with AES-256 encryption for
enhanced security in healthcare data protection.

The three-stage process:
1. Polynomial transformation (obfuscation)
2. AES-256 encryption (proven security)  
3. Combined result with integrity protection

Author: CPDPM Research Team
"""

import os
import hashlib
import hmac
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import json
import base64
from dataclasses import asdict

from cpdpm_core import CPDPMCore, PolynomialKey


class CPDPMHybrid:
    """
    Hybrid encryption implementation combining CPDPM polynomial 
    transformations with AES-256 encryption.
    """
    
    def __init__(self, prime_modulus: int = 2**31 - 1):
        """
        Initialize CPDPM hybrid encryption.
        
        Args:
            prime_modulus: Prime modulus for polynomial operations
        """
        self.cpdpm_core = CPDPMCore(prime_modulus)
        self.backend = default_backend()
        
    def _generate_aes_key(self, password: bytes, salt: bytes) -> bytes:
        """Generate AES key from password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(password)
    
    def _pad_data(self, data: bytes) -> bytes:
        """Apply PKCS7 padding to data."""
        padder = PKCS7(128).padder()
        padded_data = padder.update(data)
        padded_data += padder.finalize()
        return padded_data
    
    def _unpad_data(self, padded_data: bytes) -> bytes:
        """Remove PKCS7 padding from data."""
        unpadder = PKCS7(128).unpadder()
        data = unpadder.update(padded_data)
        data += unpadder.finalize()
        return data
    
    def _compute_integrity_hash(self, data: bytes, key: bytes) -> bytes:
        """Compute HMAC for data integrity."""
        return hmac.new(key, data, hashlib.sha256).digest()
    
    def encrypt(self, 
               plaintext: bytes, 
               password: str,
               context: Optional[str] = None,
               polynomial_degree: int = 5) -> dict:
        """
        Encrypt data using CPDPM hybrid approach.
        
        Process:
        1. Apply polynomial transformation
        2. Encrypt with AES-256
        3. Add integrity protection
        
        Args:
            plaintext: Data to encrypt
            password: Encryption password
            context: Optional context for polynomial key generation
            polynomial_degree: Degree of polynomial transformation
            
        Returns:
            Dictionary containing encrypted data and metadata
        """
        # Step 1: Polynomial transformation
        poly_transformed, poly_key = self.cpdpm_core.transform_data_block(
            plaintext, context
        )
        
        # Generate cryptographic components
        salt = os.urandom(16)
        iv = os.urandom(16)
        aes_key = self._generate_aes_key(password.encode(), salt)
        
        # Step 2: AES-256 encryption
        padded_data = self._pad_data(poly_transformed)
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        aes_encrypted = encryptor.update(padded_data) + encryptor.finalize()
        
        # Step 3: Integrity protection
        integrity_key = hashlib.sha256(aes_key + b'integrity').digest()
        integrity_hash = self._compute_integrity_hash(aes_encrypted, integrity_key)
        
        # Package results
        encrypted_package = {
            'ciphertext': base64.b64encode(aes_encrypted).decode('utf-8'),
            'salt': base64.b64encode(salt).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'integrity_hash': base64.b64encode(integrity_hash).decode('utf-8'),
            'polynomial_key': self._serialize_polynomial_key(poly_key),
            'metadata': {
                'version': '1.0',
                'algorithm': 'CPDPM-AES256',
                'polynomial_degree': polynomial_degree,
                'context_hash': hashlib.sha256(
                    (context or '').encode()
                ).hexdigest(),
                'plaintext_length': len(plaintext)
            }
        }
        
        return encrypted_package
    
    def decrypt(self, encrypted_package: dict, password: str) -> bytes:
        """
        Decrypt data using CPDPM hybrid approach.
        
        Process:
        1. Verify integrity
        2. Decrypt with AES-256
        3. Apply inverse polynomial transformation
        
        Args:
            encrypted_package: Encrypted data package from encrypt()
            password: Decryption password
            
        Returns:
            Original plaintext data
            
        Raises:
            ValueError: If decryption fails or integrity check fails
        """
        try:
            # Extract components
            ciphertext = base64.b64decode(encrypted_package['ciphertext'])
            salt = base64.b64decode(encrypted_package['salt'])
            iv = base64.b64decode(encrypted_package['iv'])
            stored_hash = base64.b64decode(encrypted_package['integrity_hash'])
            poly_key = self._deserialize_polynomial_key(
                encrypted_package['polynomial_key']
            )
            
            # Regenerate AES key
            aes_key = self._generate_aes_key(password.encode(), salt)
            
            # Step 1: Verify integrity
            integrity_key = hashlib.sha256(aes_key + b'integrity').digest()
            computed_hash = self._compute_integrity_hash(ciphertext, integrity_key)
            
            if not hmac.compare_digest(stored_hash, computed_hash):
                raise ValueError("Integrity check failed - data may be corrupted")
            
            # Step 2: AES decryption
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.CBC(iv),
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            padded_decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove padding
            aes_decrypted = self._unpad_data(padded_decrypted)
            
            # Step 3: Inverse polynomial transformation
            plaintext = self.cpdpm_core.recover_data_block(aes_decrypted, poly_key)
            
            return plaintext
            
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def _serialize_polynomial_key(self, key: PolynomialKey) -> dict:
        """Serialize polynomial key to dictionary."""
        return asdict(key)
    
    def _deserialize_polynomial_key(self, key_dict: dict) -> PolynomialKey:
        """Deserialize polynomial key from dictionary."""
        return PolynomialKey(**key_dict)
    
    def encrypt_file(self, 
                    input_file: str, 
                    output_file: str,
                    password: str,
                    context: Optional[str] = None,
                    chunk_size: int = 64 * 1024) -> dict:
        """
        Encrypt a file using CPDPM hybrid encryption.
        
        Args:
            input_file: Path to input file
            output_file: Path to output encrypted file
            password: Encryption password
            context: Optional context for key generation
            chunk_size: Size of chunks for processing large files
            
        Returns:
            Encryption metadata
        """
        with open(input_file, 'rb') as infile:
            data = infile.read()
        
        encrypted_package = self.encrypt(data, password, context)
        
        with open(output_file, 'w') as outfile:
            json.dump(encrypted_package, outfile, indent=2)
        
        return {
            'input_file': input_file,
            'output_file': output_file,
            'original_size': len(data),
            'encrypted_size': len(json.dumps(encrypted_package)),
            'algorithm': 'CPDPM-AES256'
        }
    
    def decrypt_file(self, 
                    encrypted_file: str,
                    output_file: str,
                    password: str) -> dict:
        """
        Decrypt a file encrypted with CPDPM hybrid encryption.
        
        Args:
            encrypted_file: Path to encrypted file
            output_file: Path to output decrypted file
            password: Decryption password
            
        Returns:
            Decryption metadata
        """
        with open(encrypted_file, 'r') as infile:
            encrypted_package = json.load(infile)
        
        decrypted_data = self.decrypt(encrypted_package, password)
        
        with open(output_file, 'wb') as outfile:
            outfile.write(decrypted_data)
        
        return {
            'encrypted_file': encrypted_file,
            'output_file': output_file,
            'decrypted_size': len(decrypted_data),
            'algorithm': encrypted_package['metadata']['algorithm']
        }
    
    def validate_encryption(self, 
                          plaintext: bytes,
                          password: str,
                          context: Optional[str] = None) -> bool:
        """
        Validate that encryption/decryption works correctly.
        
        Args:
            plaintext: Test data
            password: Test password
            context: Test context
            
        Returns:
            True if validation passes, False otherwise
        """
        try:
            encrypted = self.encrypt(plaintext, password, context)
            decrypted = self.decrypt(encrypted, password)
            return plaintext == decrypted
        except Exception:
            return False


class CPDPMKeyManager:
    """
    Key management utilities for CPDPM hybrid encryption.
    """
    
    def __init__(self):
        """Initialize key manager."""
        pass
    
    def generate_secure_password(self, length: int = 32) -> str:
        """
        Generate a cryptographically secure password.
        
        Args:
            length: Password length in characters
            
        Returns:
            Secure password string
        """
        # Use URL-safe base64 encoding for readable passwords
        random_bytes = os.urandom(length * 3 // 4)
        return base64.urlsafe_b64encode(random_bytes).decode('utf-8')[:length]
    
    def derive_context_from_healthcare_data(self, 
                                          patient_id: str,
                                          timestamp: str,
                                          data_type: str) -> str:
        """
        Generate context string from healthcare metadata.
        
        Args:
            patient_id: Patient identifier
            timestamp: Data timestamp
            data_type: Type of medical data
            
        Returns:
            Context string for CPDPM encryption
        """
        context_components = [
            f"patient:{patient_id}",
            f"timestamp:{timestamp}",
            f"datatype:{data_type}"
        ]
        return "|".join(context_components)
    
    def estimate_security_strength(self, 
                                 polynomial_degree: int,
                                 password_entropy: float) -> dict:
        """
        Estimate the security strength of CPDPM configuration.
        
        Args:
            polynomial_degree: Degree of polynomial transformation
            password_entropy: Estimated entropy of password in bits
            
        Returns:
            Security strength analysis
        """
        # Rough estimates for academic purposes
        aes_strength = 256  # AES-256 security
        poly_strength = polynomial_degree * 8  # Rough polynomial complexity
        
        combined_strength = min(aes_strength, password_entropy) + poly_strength * 0.5
        
        return {
            'aes_security_bits': aes_strength,
            'polynomial_complexity': poly_strength,
            'password_entropy_bits': password_entropy,
            'estimated_combined_strength': combined_strength,
            'security_level': 'High' if combined_strength > 128 else 'Medium' if combined_strength > 80 else 'Low'
        }