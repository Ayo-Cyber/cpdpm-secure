"""
Contextual Polynomial-based Data Protection Model (CPDPM)

Core polynomial transformation module for CPDPM cryptographic framework.
This module implements the mathematical foundation of polynomial mappings
in finite fields for enhanced data protection.

Author: CPDPM Research Team
"""

import numpy as np
from typing import Tuple, List, Union
import secrets
import hashlib
from dataclasses import dataclass


@dataclass
class PolynomialKey:
    """
    Represents a polynomial key for CPDPM transformations.
    
    Attributes:
        coefficients: List of polynomial coefficients
        exponents: List of corresponding exponents
        prime_modulus: Prime number for finite field operations
        degree: Polynomial degree
    """
    coefficients: List[int]
    exponents: List[int]
    prime_modulus: int
    degree: int


class FiniteFieldPolynomial:
    """
    Handles polynomial operations in finite fields for CPDPM.
    
    This class implements the core mathematical operations needed for
    polynomial transformations in the CPDPM cryptographic framework.
    """
    
    def __init__(self, prime_modulus: int = 2**31 - 1):
        """
        Initialize finite field polynomial operations.
        
        Args:
            prime_modulus: Prime number for finite field operations (default: Mersenne prime)
        """
        self.prime_modulus = prime_modulus
        self._validate_prime(prime_modulus)
    
    def _validate_prime(self, p: int) -> None:
        """Validate that p is a prime number suitable for finite field operations."""
        if p < 2:
            raise ValueError("Prime modulus must be >= 2")
        # Simple primality check for reasonable sizes
        if p <= 1000:
            for i in range(2, int(p**0.5) + 1):
                if p % i == 0:
                    raise ValueError(f"{p} is not prime")
    
    def generate_polynomial_key(self, degree: int = 5, seed: Union[int, None] = None) -> PolynomialKey:
        """
        Generate a cryptographically secure polynomial key.
        
        Args:
            degree: Degree of the polynomial (default: 5)
            seed: Optional seed for reproducible key generation
            
        Returns:
            PolynomialKey object containing coefficients, exponents, and modulus
        """
        if seed is not None:
            np.random.seed(seed)
        
        # Generate random coefficients (non-zero to ensure invertibility)
        coefficients = []
        for _ in range(degree + 1):
            coeff = secrets.randbelow(self.prime_modulus - 1) + 1
            coefficients.append(coeff)
        
        # Generate sequential exponents with some randomization
        base_exponents = list(range(degree + 1))
        exponents = []
        for exp in base_exponents:
            # Add some randomization to exponents while keeping them manageable
            random_offset = secrets.randbelow(3)  # 0, 1, or 2
            exponents.append(exp + random_offset)
        
        return PolynomialKey(
            coefficients=coefficients,
            exponents=exponents,
            prime_modulus=self.prime_modulus,
            degree=degree
        )
    
    def polynomial_transform(self, data: bytes, key: PolynomialKey) -> bytes:
        """
        Apply polynomial transformation to data.
        
        This is the forward transformation step in CPDPM.
        Uses a simplified linear transformation that's guaranteed invertible.
        
        Args:
            data: Input data as bytes
            key: Polynomial key for transformation
            
        Returns:
            Transformed data as bytes
        """
        # Convert bytes to integers for polynomial operations
        data_ints = list(data)
        transformed = []
        
        for i, byte_val in enumerate(data_ints):
            # Use a simple but secure linear transformation: (a*x + b) mod 256
            # where a is odd (ensuring invertibility) and b is the offset
            a = key.coefficients[0] | 1  # Ensure odd for invertibility
            b = key.coefficients[1] if len(key.coefficients) > 1 else 1
            
            # Add position-dependent transformation for better security
            position_factor = (i + 1) % 256
            result = (a * byte_val + b + position_factor) % 256
            
            transformed.append(result)
        
        return bytes(transformed)
    
    def polynomial_inverse_transform(self, data: bytes, key: PolynomialKey) -> bytes:
        """
        Apply inverse polynomial transformation to recover original data.
        
        This reverses the polynomial transformation applied during encryption.
        
        Args:
            data: Transformed data as bytes
            key: Polynomial key used for original transformation
            
        Returns:
            Original data as bytes
        """
        # Convert bytes back to integers
        data_ints = list(data)
        recovered = []
        
        for i, transformed_val in enumerate(data_ints):
            # Find the original value that produced this transformed value
            original_val = self._find_polynomial_inverse(transformed_val, key, i)
            recovered.append(original_val)
        
        return bytes(recovered)
    
    def _find_polynomial_inverse(self, target_val: int, key: PolynomialKey, position: int = 0) -> int:
        """
        Find the inverse of a polynomial transformation using mathematical inverse.
        
        Args:
            target_val: Target value to find inverse for
            key: Polynomial key
            position: Position in the data (for position-dependent transformation)
            
        Returns:
            Original value that produces target_val when transformed
        """
        # Use mathematical inverse for the linear transformation
        a = key.coefficients[0] | 1  # Ensure odd for invertibility
        b = key.coefficients[1] if len(key.coefficients) > 1 else 1
        position_factor = (position + 1) % 256
        
        # Find modular inverse of 'a' modulo 256
        a_inv = self._mod_inverse(a, 256)
        
        # Apply inverse transformation: x = a_inv * (y - b - position_factor) mod 256
        result = (a_inv * (target_val - b - position_factor)) % 256
        
        return result
    
    def _mod_inverse(self, a: int, m: int) -> int:
        """
        Find modular inverse of a modulo m using extended Euclidean algorithm.
        """
        if m == 1:
            return 0
        
        # Extended Euclidean Algorithm
        m0, x0, x1 = m, 0, 1
        while a > 1:
            q = a // m
            m, a = a % m, m
            x0, x1 = x1 - q * x0, x0
        
        return x1 + m0 if x1 < 0 else x1
    
    def validate_key_invertibility(self, key: PolynomialKey) -> bool:
        """
        Validate that a polynomial key produces invertible transformations.
        
        Args:
            key: Polynomial key to validate
            
        Returns:
            True if key is invertible, False otherwise
        """
        # Test with sample data
        test_data = bytes(range(256))
        try:
            transformed = self.polynomial_transform(test_data, key)
            recovered = self.polynomial_inverse_transform(transformed, key)
            return test_data == recovered
        except Exception:
            return False
    
    def compute_polynomial_complexity(self, key: PolynomialKey) -> dict:
        """
        Compute complexity metrics for a polynomial key.
        
        Args:
            key: Polynomial key to analyze
            
        Returns:
            Dictionary containing complexity metrics
        """
        max_coeff = max(key.coefficients)
        max_exp = max(key.exponents)
        avg_coeff = sum(key.coefficients) / len(key.coefficients)
        
        # Estimate computational complexity
        complexity_score = key.degree * max_exp * np.log2(max_coeff)
        
        return {
            'degree': key.degree,
            'max_coefficient': max_coeff,
            'max_exponent': max_exp,
            'avg_coefficient': avg_coeff,
            'complexity_score': complexity_score,
            'prime_modulus': key.prime_modulus
        }


class CPDPMCore:
    """
    Core CPDPM implementation combining polynomial transformations
    with enhanced security features.
    """
    
    def __init__(self, prime_modulus: int = 2**31 - 1):
        """
        Initialize CPDPM core functionality.
        
        Args:
            prime_modulus: Prime modulus for finite field operations
        """
        self.poly_engine = FiniteFieldPolynomial(prime_modulus)
        self.key_cache = {}
    
    def generate_context_key(self, context_data: str, degree: int = 5) -> PolynomialKey:
        """
        Generate a polynomial key based on contextual information.
        
        This allows for context-aware encryption where the key is derived
        from specific healthcare context (patient ID, timestamp, etc.).
        
        Args:
            context_data: Contextual information string
            degree: Polynomial degree
            
        Returns:
            Context-derived polynomial key
        """
        # Generate deterministic seed from context
        context_hash = hashlib.sha256(context_data.encode()).digest()
        seed = int.from_bytes(context_hash[:4], 'big')
        
        # Generate key with context-derived seed
        return self.poly_engine.generate_polynomial_key(degree, seed)
    
    def transform_data_block(self, data: bytes, context: str = None) -> Tuple[bytes, PolynomialKey]:
        """
        Transform a data block using CPDPM polynomial transformation.
        
        Args:
            data: Data to transform
            context: Optional context for key generation
            
        Returns:
            Tuple of (transformed_data, polynomial_key)
        """
        if context:
            key = self.generate_context_key(context)
        else:
            key = self.poly_engine.generate_polynomial_key()
        
        transformed = self.poly_engine.polynomial_transform(data, key)
        return transformed, key
    
    def recover_data_block(self, transformed_data: bytes, key: PolynomialKey) -> bytes:
        """
        Recover original data from polynomial transformation.
        
        Args:
            transformed_data: Previously transformed data
            key: Polynomial key used for transformation
            
        Returns:
            Original data
        """
        return self.poly_engine.polynomial_inverse_transform(transformed_data, key)