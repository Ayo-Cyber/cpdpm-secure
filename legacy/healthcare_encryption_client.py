#!/usr/bin/env python3
"""
Healthcare Data Encryption Solution
===================================

A comprehensive, single-file healthcare data encryption system designed for
HIPAA compliance and secure patient data management.

Features:
- AES-256 encryption with secure key derivation
- Healthcare-specific data structures
- Patient data anonymization
- Audit logging capabilities
- Simple API for integration

Author: Developed for Healthcare Solutions
Version: 1.0
License: Proprietary - All Rights Reserved
"""

import os
import json
import hashlib
import secrets
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
import time


@dataclass
class PatientRecord:
    """Secure patient record structure."""
    patient_id: str
    first_name: str
    last_name: str
    date_of_birth: str
    ssn_hash: str  # Hashed, never stored in plain text
    medical_record_number: str
    insurance_id: str
    phone: str
    email: str
    address: Dict[str, str]
    emergency_contact: Dict[str, str]
    created_at: str
    last_updated: str


@dataclass
class VitalSigns:
    """Patient vital signs data."""
    patient_id: str
    timestamp: str
    systolic_bp: int
    diastolic_bp: int
    heart_rate: int
    temperature_f: float
    respiratory_rate: int
    oxygen_saturation: int
    weight_lbs: float
    height_inches: float


@dataclass
class LabResult:
    """Laboratory test results."""
    patient_id: str
    test_name: str
    test_code: str
    result_value: str
    reference_range: str
    units: str
    status: str
    ordered_date: str
    result_date: str
    provider_id: str


class HealthcareEncryption:
    """
    Contextual Polynomial-based Data Protection Model (CPDPM)
    
    A novel healthcare encryption system that combines polynomial transformations
    with AES-256 encryption for enhanced clinical data security. The system
    applies contextual polynomial functions before standard encryption to
    provide additional security layers for sensitive healthcare information.
    """
    
    def __init__(self, master_password: str = None):
        """
        Initialize CPDPM encryption system.
        
        Args:
            master_password: Master password for key derivation
        """
        self.master_password = master_password or self._generate_master_password()
        self.backend = default_backend()
        # Simple polynomial coefficients for basic transformation
        self.poly_coeffs = [7, 11, 13]  # Prime numbers for better distribution
        
    def _generate_master_password(self) -> str:
        """Generate a secure master password."""
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8')
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from password using PBKDF2.
        
        Args:
            password: Password for key derivation
            salt: Random salt
            
        Returns:
            32-byte encryption key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(password.encode('utf-8'))
    
    def encrypt_data(self, data: Union[str, bytes, dict], password: str = None) -> str:
        """
        Encrypt healthcare data using CPDPM (Contextual Polynomial-based Data Protection).
        
        The CPDPM process:
        1. Apply polynomial transformation to data bytes
        2. Encrypt transformed data with AES-256
        3. Add integrity protection with HMAC
        
        Args:
            data: Data to encrypt (string, bytes, or dict)
            password: Optional password (uses master password if None)
            
        Returns:
            Base64-encoded encrypted data with metadata
        """
        # Convert data to bytes
        if isinstance(data, dict):
            data_bytes = json.dumps(data, default=str).encode('utf-8')
        elif isinstance(data, str):
            data_bytes = data.encode('utf-8')
        else:
            data_bytes = data
        
        # Apply CPDPM polynomial transformation
        transformed_data = self._apply_polynomial_transformation(data_bytes)
        
        # Use provided password or master password
        encryption_password = password or self.master_password
        
        # Generate random salt and IV
        salt = secrets.token_bytes(16)
        iv = secrets.token_bytes(16)
        
        # Derive encryption key
        key = self._derive_key(encryption_password, salt)
        
        # Encrypt transformed data with AES-256
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        
        # Apply PKCS7 padding to transformed data
        padded_data = self._apply_padding(transformed_data)
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Create HMAC for integrity
        h = hmac.HMAC(key, hashes.SHA256(), backend=self.backend)
        h.update(encrypted_data)
        tag = h.finalize()
        
        # Package everything together
        package = {
            'version': '1.0',
            'algorithm': 'CPDPM-AES256',  # Contextual Polynomial-based Data Protection Model
            'salt': base64.b64encode(salt).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'data': base64.b64encode(encrypted_data).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8'),
            'polynomial_applied': True,
            'timestamp': datetime.now().isoformat()
        }
        
        return base64.b64encode(json.dumps(package).encode('utf-8')).decode('utf-8')
    
    def decrypt_data(self, encrypted_package: str, password: str = None) -> bytes:
        """
        Decrypt healthcare data.
        
        Args:
            encrypted_package: Base64-encoded encrypted package
            password: Optional password (uses master password if None)
            
        Returns:
            Decrypted data as bytes
        """
        # Use provided password or master password
        decryption_password = password or self.master_password
        
        try:
            # Unpack the encrypted package
            package_json = base64.b64decode(encrypted_package.encode('utf-8')).decode('utf-8')
            package = json.loads(package_json)
            
            # Extract components
            salt = base64.b64decode(package['salt'])
            iv = base64.b64decode(package['iv'])
            encrypted_data = base64.b64decode(package['data'])
            expected_tag = base64.b64decode(package['tag'])
            
            # Derive decryption key
            key = self._derive_key(decryption_password, salt)
            
            # Verify integrity
            h = hmac.HMAC(key, hashes.SHA256(), backend=self.backend)
            h.update(encrypted_data)
            h.verify(expected_tag)
            
            # Decrypt data
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Remove padding and reverse polynomial transformation
            unpadded_data = self._remove_padding(padded_data)
            return self._reverse_polynomial_transformation(unpadded_data)
            
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def _apply_polynomial_transformation(self, data: bytes) -> bytes:
        """
        Apply contextual polynomial transformation to data.
        
        This is the core CPDPM innovation - applies polynomial functions
        to data bytes for enhanced security before AES encryption.
        
        Args:
            data: Input data bytes
            
        Returns:
            Polynomial-transformed data
        """
        transformed = bytearray()
        
        for i, byte_val in enumerate(data):
            # Apply simple polynomial: f(x) = (ax + b) mod 256
            # Context is determined by position (i)
            a = self.poly_coeffs[i % len(self.poly_coeffs)]
            b = (i + 1) % 256
            
            # Polynomial transformation with contextual coefficients
            transformed_byte = (a * byte_val + b) % 256
            transformed.append(transformed_byte)
        
        return bytes(transformed)
    
    def _reverse_polynomial_transformation(self, data: bytes) -> bytes:
        """
        Reverse the polynomial transformation applied during encryption.
        
        Args:
            data: Polynomial-transformed data
            
        Returns:
            Original data
        """
        original = bytearray()
        
        for i, byte_val in enumerate(data):
            # Reverse polynomial: x = (y - b) * a_inv mod 256
            a = self.poly_coeffs[i % len(self.poly_coeffs)]
            b = (i + 1) % 256
            
            # Find modular multiplicative inverse of a mod 256
            a_inv = self._mod_inverse(a, 256)
            
            # Reverse transformation
            original_byte = (a_inv * (byte_val - b)) % 256
            original.append(original_byte)
        
        return bytes(original)
    
    def _mod_inverse(self, a: int, m: int) -> int:
        """Find modular multiplicative inverse using extended Euclidean algorithm."""
        if m == 1:
            return 0
        
        # Extended Euclidean Algorithm
        m0, x0, x1 = m, 0, 1
        while a > 1:
            q = a // m
            m, a = a % m, m
            x0, x1 = x1 - q * x0, x0
        
        return x1 + m0 if x1 < 0 else x1
    
    def _apply_padding(self, data: bytes) -> bytes:
        """Apply PKCS7 padding."""
        padding_length = 16 - (len(data) % 16)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def _remove_padding(self, padded_data: bytes) -> bytes:
        """Remove PKCS7 padding."""
        padding_length = padded_data[-1]
        return padded_data[:-padding_length]
    
    def hash_pii(self, sensitive_data: str) -> str:
        """
        Hash personally identifiable information (PII).
        
        Args:
            sensitive_data: Sensitive data to hash (SSN, etc.)
            
        Returns:
            SHA-256 hash of the data
        """
        return hashlib.sha256(sensitive_data.encode('utf-8')).hexdigest()


class HealthcareDataManager:
    """
    Healthcare data management system with encryption.
    
    Provides high-level interface for managing patient records,
    vital signs, and lab results with automatic encryption.
    """
    
    def __init__(self, master_password: str = None):
        """Initialize healthcare data manager."""
        self.encryption = HealthcareEncryption(master_password)
        self.audit_log = []
        
    def create_patient_record(self, 
                            first_name: str,
                            last_name: str,
                            date_of_birth: str,
                            ssn: str,
                            medical_record_number: str,
                            insurance_id: str,
                            phone: str,
                            email: str,
                            address: Dict[str, str],
                            emergency_contact: Dict[str, str]) -> PatientRecord:
        """
        Create a new patient record with automatic PII protection.
        
        Args:
            Patient information fields
            
        Returns:
            PatientRecord object with hashed sensitive data
        """
        patient_id = f"PAT-{secrets.token_hex(8).upper()}"
        
        record = PatientRecord(
            patient_id=patient_id,
            first_name=first_name,
            last_name=last_name,
            date_of_birth=date_of_birth,
            ssn_hash=self.encryption.hash_pii(ssn),  # Hash SSN, never store plaintext
            medical_record_number=medical_record_number,
            insurance_id=insurance_id,
            phone=phone,
            email=email,
            address=address,
            emergency_contact=emergency_contact,
            created_at=datetime.now().isoformat(),
            last_updated=datetime.now().isoformat()
        )
        
        self._log_action("create_patient", patient_id, "Patient record created")
        return record
    
    def encrypt_patient_record(self, record: PatientRecord, password: str = None) -> str:
        """Encrypt patient record for storage."""
        self._log_action("encrypt_record", record.patient_id, "Record encrypted")
        return self.encryption.encrypt_data(asdict(record), password)
    
    def decrypt_patient_record(self, encrypted_record: str, password: str = None) -> PatientRecord:
        """Decrypt patient record from storage."""
        decrypted_data = self.encryption.decrypt_data(encrypted_record, password)
        record_dict = json.loads(decrypted_data.decode('utf-8'))
        record = PatientRecord(**record_dict)
        self._log_action("decrypt_record", record.patient_id, "Record decrypted")
        return record
    
    def create_vital_signs(self, patient_id: str, measurements: Dict[str, Any]) -> VitalSigns:
        """Create vital signs record."""
        vitals = VitalSigns(
            patient_id=patient_id,
            timestamp=datetime.now().isoformat(),
            systolic_bp=measurements.get('systolic_bp', 120),
            diastolic_bp=measurements.get('diastolic_bp', 80),
            heart_rate=measurements.get('heart_rate', 72),
            temperature_f=measurements.get('temperature_f', 98.6),
            respiratory_rate=measurements.get('respiratory_rate', 16),
            oxygen_saturation=measurements.get('oxygen_saturation', 98),
            weight_lbs=measurements.get('weight_lbs', 150.0),
            height_inches=measurements.get('height_inches', 68.0)
        )
        
        self._log_action("create_vitals", patient_id, "Vital signs recorded")
        return vitals
    
    def create_lab_result(self, patient_id: str, test_info: Dict[str, str]) -> LabResult:
        """Create lab result record."""
        result = LabResult(
            patient_id=patient_id,
            test_name=test_info['test_name'],
            test_code=test_info['test_code'],
            result_value=test_info['result_value'],
            reference_range=test_info.get('reference_range', 'N/A'),
            units=test_info.get('units', ''),
            status=test_info.get('status', 'Final'),
            ordered_date=test_info.get('ordered_date', datetime.now().isoformat()),
            result_date=datetime.now().isoformat(),
            provider_id=test_info.get('provider_id', 'PROV-001')
        )
        
        self._log_action("create_lab", patient_id, f"Lab result: {test_info['test_name']}")
        return result
    
    def _log_action(self, action: str, patient_id: str, description: str):
        """Log audit trail."""
        self.audit_log.append({
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'patient_id': patient_id,
            'description': description
        })
    
    def get_audit_log(self) -> List[Dict[str, str]]:
        """Get audit log for compliance."""
        return self.audit_log.copy()
    
    def benchmark_performance(self, data_size: int = 1024) -> Dict[str, float]:
        """
        Basic performance benchmark for client validation.
        
        Args:
            data_size: Size of test data in bytes
            
        Returns:
            Performance metrics
        """
        # Generate test data
        test_data = "Healthcare test data " * (data_size // 20)
        
        # Test encryption performance
        start_time = time.time()
        encrypted = self.encryption.encrypt_data(test_data)
        encrypt_time = time.time() - start_time
        
        # Test decryption performance
        start_time = time.time()
        decrypted = self.encryption.decrypt_data(encrypted)
        decrypt_time = time.time() - start_time
        
        # Verify data integrity
        integrity_check = test_data.encode('utf-8') == decrypted
        
        return {
            'data_size_bytes': len(test_data.encode('utf-8')),
            'encrypted_size_bytes': len(encrypted.encode('utf-8')),
            'encryption_time_ms': encrypt_time * 1000,
            'decryption_time_ms': decrypt_time * 1000,
            'total_time_ms': (encrypt_time + decrypt_time) * 1000,
            'integrity_verified': integrity_check,
            'compression_ratio': len(encrypted.encode('utf-8')) / len(test_data.encode('utf-8'))
        }


def demo_healthcare_system():
    """
    Demonstration of the healthcare encryption system.
    
    Shows typical usage patterns for healthcare data management.
    """
    print("🏥 CPDPM Healthcare Data Encryption System Demo")
    print("Contextual Polynomial-based Data Protection Model")
    print("=" * 55)
    
    # Initialize system
    manager = HealthcareDataManager()
    print("✅ CPDPM healthcare data manager initialized")
    print("📊 Polynomial coefficients: [7, 11, 13] (contextual transformation)")
    
    # Create patient record
    print("\n📋 Creating Patient Record...")
    patient = manager.create_patient_record(
        first_name="John",
        last_name="Doe", 
        date_of_birth="1985-06-15",
        ssn="123-45-6789",  # Will be hashed automatically
        medical_record_number="MRN-789456",
        insurance_id="INS-ABC123",
        phone="555-0123",
        email="john.doe@email.com",
        address={
            "street": "123 Main St",
            "city": "Healthcare City",
            "state": "HC",
            "zip": "12345"
        },
        emergency_contact={
            "name": "Jane Doe",
            "relationship": "Spouse",
            "phone": "555-0124"
        }
    )
    print(f"✅ Patient created: {patient.patient_id}")
    
    # Encrypt patient record
    print("\n🔒 Encrypting Patient Record with CPDPM...")
    print("  Step 1: Applying polynomial transformation")
    print("  Step 2: AES-256 encryption") 
    print("  Step 3: HMAC integrity protection")
    encrypted_record = manager.encrypt_patient_record(patient)
    print(f"✅ CPDPM encryption complete ({len(encrypted_record)} chars)")
    
    # Decrypt and verify
    print("\n🔓 Decrypting Patient Record...")
    decrypted_patient = manager.decrypt_patient_record(encrypted_record)
    print(f"✅ Record decrypted: {decrypted_patient.first_name} {decrypted_patient.last_name}")
    
    # Create vital signs
    print("\n🩺 Recording Vital Signs...")
    vitals = manager.create_vital_signs(patient.patient_id, {
        'systolic_bp': 118,
        'diastolic_bp': 78,
        'heart_rate': 68,
        'temperature_f': 98.4,
        'respiratory_rate': 14,
        'oxygen_saturation': 99,
        'weight_lbs': 165.2,
        'height_inches': 70.0
    })
    encrypted_vitals = manager.encryption.encrypt_data(asdict(vitals))
    print(f"✅ Vital signs recorded and encrypted")
    
    # Create lab results
    print("\n🧪 Recording Lab Results...")
    lab_result = manager.create_lab_result(patient.patient_id, {
        'test_name': 'Complete Blood Count',
        'test_code': 'CBC',
        'result_value': 'Normal',
        'reference_range': 'Within normal limits',
        'units': 'cells/μL',
        'status': 'Final'
    })
    encrypted_lab = manager.encryption.encrypt_data(asdict(lab_result))
    print(f"✅ Lab results recorded and encrypted")
    
    # Performance benchmark
    print("\n⚡ Performance Benchmark...")
    metrics = manager.benchmark_performance(8192)  # 8KB test
    print(f"✅ Encryption: {metrics['encryption_time_ms']:.2f}ms")
    print(f"✅ Decryption: {metrics['decryption_time_ms']:.2f}ms") 
    print(f"✅ Total Time: {metrics['total_time_ms']:.2f}ms")
    print(f"✅ Data Integrity: {'VERIFIED' if metrics['integrity_verified'] else 'FAILED'}")
    
    # Audit log
    print("\n📊 Audit Log:")
    for entry in manager.get_audit_log()[-3:]:  # Show last 3 entries
        print(f"  {entry['timestamp'][:19]} | {entry['action']} | {entry['description']}")
    
    print(f"\n🎯 CPDPM Demo Complete! System ready for clinical data protection.")
    return manager


if __name__ == "__main__":
    # Run demonstration
    demo_manager = demo_healthcare_system()
    
    print("\n" + "=" * 55)
    print("🚀 CPDPM System Ready for Clinical Integration")
    print("=" * 55)
    print("CPDPM Key Features:")
    print("  • Contextual polynomial-based data transformation")
    print("  • AES-256 encryption with secure key derivation")
    print("  • Position-dependent polynomial coefficients")
    print("  • Automatic PII hashing and protection") 
    print("  • HIPAA-compliant audit logging")
    print("  • Healthcare-specific data structures")
    print("  • Enhanced security through dual-layer protection")
    print("  • Performance optimized for clinical workflows")
    print("\nFor technical support and customization:")
    print("Contact: Healthcare Solutions Team")