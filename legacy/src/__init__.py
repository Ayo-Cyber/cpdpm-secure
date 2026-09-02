"""
CPDPM - Contextual Polynomial-based Data Protection Model

A novel cryptographic framework for healthcare data protection combining
polynomial transformations with standard encryption methods.

Main modules:
- cpdpm_core: Core polynomial transformation functions
- cpdpm_hybrid: Hybrid encryption combining CPDPM with AES-256
- synthetic_data: Healthcare data generators for testing
- benchmarks: Performance comparison tools
- security_analysis: Cryptographic strength analysis tools
"""

__version__ = "1.0.0"
__author__ = "CPDPM Research Team"

# Import main classes for easy access
from .cpdpm_core import CPDPMCore, FiniteFieldPolynomial, PolynomialKey
from .cpdpm_hybrid import CPDPMHybrid, CPDPMKeyManager

__all__ = [
    'CPDPMCore',
    'FiniteFieldPolynomial', 
    'PolynomialKey',
    'CPDPMHybrid',
    'CPDPMKeyManager'
]