"""
Comprehensive Test Suite for CPDPM

This module provides extensive unit tests, integration tests, and security
validation tests for the Contextual Polynomial-based Data Protection Model.

Author: CPDPM Research Team
"""

import unittest
import pytest
import time
import os
import json
import tempfile
from typing import Dict, List, Tuple
import numpy as np

# Add src to path for imports
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Import CPDPM modules
from cpdpm_core import CPDPMCore, FiniteFieldPolynomial, PolynomialKey
from cpdpm_hybrid import CPDPMHybrid, CPDPMKeyManager
from synthetic_data import SyntheticHealthcareGenerator, EncryptionDemoData
from benchmarks import PerformanceBenchmark, SecurityBenchmark
from security_analysis import ComprehensiveSecurityValidator


class TestFiniteFieldPolynomial(unittest.TestCase):
    """Test cases for polynomial operations in finite fields."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.poly_engine = FiniteFieldPolynomial(prime_modulus=2**31 - 1)
    
    def test_polynomial_key_generation(self):
        """Test polynomial key generation."""
        key = self.poly_engine.generate_polynomial_key(degree=5, seed=42)
        
        self.assertIsInstance(key, PolynomialKey)
        self.assertEqual(key.degree, 5)
        self.assertEqual(len(key.coefficients), 6)  # degree + 1
        self.assertEqual(len(key.exponents), 6)
        self.assertEqual(key.prime_modulus, self.poly_engine.prime_modulus)
        
        # Test reproducibility with same seed
        key2 = self.poly_engine.generate_polynomial_key(degree=5, seed=42)
        self.assertEqual(key.coefficients, key2.coefficients)
        self.assertEqual(key.exponents, key2.exponents)
    
    def test_polynomial_transformation_invertibility(self):
        """Test that polynomial transformations are invertible."""
        key = self.poly_engine.generate_polynomial_key(degree=3, seed=123)
        
        # Test various data sizes
        test_data_list = [
            b"Hello",
            b"Healthcare data test",
            b"A" * 100,  # Repeated character
            bytes(range(256))  # All possible bytes
        ]
        
        for test_data in test_data_list:
            with self.subTest(data_length=len(test_data)):
                # Apply transformation and inverse
                transformed = self.poly_engine.polynomial_transform(test_data, key)
                recovered = self.poly_engine.polynomial_inverse_transform(transformed, key)
                
                self.assertEqual(test_data, recovered)
                self.assertIsInstance(transformed, bytes)
                self.assertEqual(len(transformed), len(test_data))
    
    def test_polynomial_complexity_calculation(self):
        """Test polynomial complexity metrics calculation."""
        key = self.poly_engine.generate_polynomial_key(degree=7, seed=456)
        
        complexity = self.poly_engine.compute_polynomial_complexity(key)
        
        self.assertIn('degree', complexity)
        self.assertIn('max_coefficient', complexity)
        self.assertIn('complexity_score', complexity)
        self.assertEqual(complexity['degree'], 7)
        self.assertGreater(complexity['complexity_score'], 0)
    
    def test_key_invertibility_validation(self):
        """Test polynomial key invertibility validation."""
        key = self.poly_engine.generate_polynomial_key(degree=4, seed=789)
        
        # Should be invertible with proper key
        is_invertible = self.poly_engine.validate_key_invertibility(key)
        self.assertTrue(is_invertible)
    
    def test_invalid_prime_modulus(self):
        """Test error handling for invalid prime modulus."""
        with self.assertRaises(ValueError):
            FiniteFieldPolynomial(prime_modulus=1)  # Invalid prime
        
        with self.assertRaises(ValueError):
            FiniteFieldPolynomial(prime_modulus=4)  # Not prime


class TestCPDPMCore(unittest.TestCase):
    """Test cases for CPDPM core functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.cpdpm_core = CPDPMCore()
    
    def test_context_key_generation(self):
        """Test context-aware key generation."""
        context1 = "patient:001:vitals"
        context2 = "patient:002:vitals"
        context3 = "patient:001:vitals"  # Same as context1
        
        key1 = self.cpdpm_core.generate_context_key(context1)
        key2 = self.cpdpm_core.generate_context_key(context2)
        key3 = self.cpdpm_core.generate_context_key(context3)
        
        # Same context should generate same key
        self.assertEqual(key1.coefficients, key3.coefficients)
        self.assertEqual(key1.exponents, key3.exponents)
        
        # Different context should generate different key
        self.assertNotEqual(key1.coefficients, key2.coefficients)
    
    def test_data_block_transformation(self):
        """Test data block transformation with and without context."""
        test_data = b"Medical record test data"
        
        # Test without context
        transformed1, key1 = self.cpdpm_core.transform_data_block(test_data)
        recovered1 = self.cpdpm_core.recover_data_block(transformed1, key1)
        self.assertEqual(test_data, recovered1)
        
        # Test with context
        context = "test_context"
        transformed2, key2 = self.cpdpm_core.transform_data_block(test_data, context)
        recovered2 = self.cpdpm_core.recover_data_block(transformed2, key2)
        self.assertEqual(test_data, recovered2)
        
        # Different transformations for same data
        self.assertNotEqual(transformed1, transformed2)


class TestCPDPMHybrid(unittest.TestCase):
    """Test cases for CPDPM hybrid encryption."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.cpdpm = CPDPMHybrid()
        self.key_manager = CPDPMKeyManager()
        
    def test_encryption_decryption_round_trip(self):
        """Test complete encryption/decryption cycle."""
        test_data = b"Confidential healthcare information"
        password = "SecureTestPassword123!"
        context = "test:encryption:cycle"
        
        # Encrypt
        encrypted_package = self.cpdpm.encrypt(test_data, password, context)
        
        # Verify package structure
        required_keys = ['ciphertext', 'salt', 'iv', 'integrity_hash', 
                        'polynomial_key', 'metadata']
        for key in required_keys:
            self.assertIn(key, encrypted_package)
        
        # Decrypt
        decrypted_data = self.cpdpm.decrypt(encrypted_package, password)
        
        # Verify correctness
        self.assertEqual(test_data, decrypted_data)
    
    def test_wrong_password_rejection(self):
        """Test that wrong password is rejected."""
        test_data = b"Sensitive medical data"
        correct_password = "CorrectPassword123!"
        wrong_password = "WrongPassword456!"
        
        encrypted_package = self.cpdpm.encrypt(test_data, correct_password)
        
        with self.assertRaises(ValueError):
            self.cpdpm.decrypt(encrypted_package, wrong_password)
    
    def test_data_tampering_detection(self):
        """Test detection of tampered encrypted data."""
        test_data = b"Critical patient information"
        password = "TestPassword789!"
        
        encrypted_package = self.cpdpm.encrypt(test_data, password)
        
        # Tamper with ciphertext
        tampered_package = encrypted_package.copy()
        import base64
        ciphertext = base64.b64decode(tampered_package['ciphertext'])
        tampered_ciphertext = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
        tampered_package['ciphertext'] = base64.b64encode(tampered_ciphertext).decode()
        
        with self.assertRaises(ValueError):
            self.cpdpm.decrypt(tampered_package, password)
    
    def test_file_encryption_decryption(self):
        """Test file-based encryption and decryption."""
        test_data = b"File encryption test data for CPDPM"
        password = "FileTestPassword!"
        
        with tempfile.TemporaryDirectory() as temp_dir:
            input_file = os.path.join(temp_dir, "input.txt")
            encrypted_file = os.path.join(temp_dir, "encrypted.json")
            output_file = os.path.join(temp_dir, "decrypted.txt")
            
            # Create input file
            with open(input_file, 'wb') as f:
                f.write(test_data)
            
            # Encrypt file
            encrypt_metadata = self.cpdpm.encrypt_file(
                input_file, encrypted_file, password
            )
            self.assertTrue(os.path.exists(encrypted_file))
            self.assertEqual(encrypt_metadata['original_size'], len(test_data))
            
            # Decrypt file
            decrypt_metadata = self.cpdpm.decrypt_file(
                encrypted_file, output_file, password
            )
            
            # Verify decrypted content
            with open(output_file, 'rb') as f:
                decrypted_data = f.read()
            
            self.assertEqual(test_data, decrypted_data)
            self.assertEqual(decrypt_metadata['decrypted_size'], len(test_data))
    
    def test_validation_function(self):
        """Test encryption validation function."""
        test_data = b"Validation test data"
        password = "ValidationPassword!"
        
        # Should validate successfully
        is_valid = self.cpdpm.validate_encryption(test_data, password)
        self.assertTrue(is_valid)


class TestCPDPMKeyManager(unittest.TestCase):
    """Test cases for CPDPM key management."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.key_manager = CPDPMKeyManager()
    
    def test_secure_password_generation(self):
        """Test secure password generation."""
        password = self.key_manager.generate_secure_password(32)
        
        self.assertEqual(len(password), 32)
        self.assertIsInstance(password, str)
        
        # Generate multiple passwords - should be different
        password2 = self.key_manager.generate_secure_password(32)
        self.assertNotEqual(password, password2)
    
    def test_healthcare_context_derivation(self):
        """Test healthcare context derivation."""
        context = self.key_manager.derive_context_from_healthcare_data(
            patient_id="TEST-001",
            timestamp="2024-01-15T10:30:00Z",
            data_type="vital_signs"
        )
        
        self.assertIn("patient:TEST-001", context)
        self.assertIn("timestamp:2024-01-15T10:30:00Z", context)
        self.assertIn("datatype:vital_signs", context)
    
    def test_security_strength_estimation(self):
        """Test security strength estimation."""
        analysis = self.key_manager.estimate_security_strength(
            polynomial_degree=5,
            password_entropy=128.0
        )
        
        required_keys = ['aes_security_bits', 'polynomial_complexity', 
                        'password_entropy_bits', 'estimated_combined_strength',
                        'security_level']
        
        for key in required_keys:
            self.assertIn(key, analysis)
        
        self.assertEqual(analysis['aes_security_bits'], 256)
        self.assertEqual(analysis['password_entropy_bits'], 128.0)
        self.assertIn(analysis['security_level'], ['Low', 'Medium', 'High'])


class TestSyntheticHealthcareGenerator(unittest.TestCase):
    """Test cases for synthetic healthcare data generation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.generator = SyntheticHealthcareGenerator(seed=42)
    
    def test_patient_record_generation(self):
        """Test patient record generation."""
        patient = self.generator.generate_patient_record()
        
        self.assertTrue(patient.patient_id.startswith('PAT-'))
        self.assertGreaterEqual(patient.age, 18)
        self.assertLessEqual(patient.age, 90)
        self.assertIn(patient.gender, ['Male', 'Female', 'Other'])
        self.assertIn(patient.blood_type, ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-'])
    
    def test_vital_signs_generation(self):
        """Test vital signs generation."""
        patient_id = "TEST-001"
        vitals = self.generator.generate_vital_signs(patient_id, 3)
        
        self.assertEqual(len(vitals), 3)
        
        for vital in vitals:
            self.assertEqual(vital.patient_id, patient_id)
            self.assertGreaterEqual(vital.heart_rate_bpm, 50)
            self.assertLessEqual(vital.heart_rate_bpm, 150)
            self.assertGreaterEqual(vital.temperature_celsius, 35.0)
            self.assertLessEqual(vital.temperature_celsius, 40.0)
    
    def test_lab_results_generation(self):
        """Test lab results generation."""
        patient_id = "TEST-001"
        labs = self.generator.generate_lab_results(patient_id, 2)
        
        self.assertGreaterEqual(len(labs), 2)
        
        for lab in labs:
            self.assertEqual(lab.patient_id, patient_id)
            self.assertIsInstance(lab.result_value, float)
            self.assertIsInstance(lab.abnormal_flag, bool)
    
    def test_medical_note_generation(self):
        """Test medical note generation."""
        patient_id = "TEST-001"
        note = self.generator.generate_medical_note(patient_id)
        
        self.assertEqual(note.patient_id, patient_id)
        self.assertTrue(len(note.content) > 50)  # Reasonable content length
        self.assertTrue(note.note_id.startswith('NOTE-'))
    
    def test_complete_dataset_generation(self):
        """Test complete dataset generation."""
        dataset = self.generator.generate_complete_patient_dataset(
            patient_count=5,
            vitals_per_patient=2,
            labs_per_patient=1,
            notes_per_patient=1
        )
        
        self.assertEqual(len(dataset['patients']), 5)
        self.assertEqual(len(dataset['vital_signs']), 10)  # 5 patients * 2 vitals
        self.assertGreaterEqual(len(dataset['lab_results']), 5)  # At least 5
        self.assertEqual(len(dataset['medical_notes']), 5)  # 5 patients * 1 note
    
    def test_hipaa_compliant_sample(self):
        """Test HIPAA compliant sample generation."""
        sample = self.generator.generate_hipaa_compliant_sample()
        
        self.assertIsInstance(sample, bytes)
        self.assertGreater(len(sample), 100)  # Reasonable size
        
        # Should be valid JSON
        sample_data = json.loads(sample.decode('utf-8'))
        self.assertIn('patient', sample_data)
        self.assertIn('vital_signs', sample_data)
        self.assertIn('lab_result', sample_data)


class TestPerformanceBenchmark(unittest.TestCase):
    """Test cases for performance benchmarking."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.benchmark = PerformanceBenchmark()
    
    def test_cpdpm_encryption_benchmark(self):
        """Test CPDPM encryption benchmarking."""
        test_data = b"Performance test data for CPDPM benchmarking"
        
        result = self.benchmark.benchmark_cpdpm_encryption(test_data)
        
        self.assertEqual(result.algorithm, "CPDPM-AES256")
        self.assertEqual(result.operation, "encrypt")
        self.assertEqual(result.data_size, len(test_data))
        self.assertGreater(result.execution_time, 0)
        self.assertTrue(result.success)
    
    def test_aes_encryption_benchmark(self):
        """Test AES encryption benchmarking."""
        test_data = b"Performance test data for AES benchmarking"
        
        result = self.benchmark.benchmark_aes_encryption(test_data)
        
        self.assertEqual(result.algorithm, "AES-256-CBC")
        self.assertEqual(result.operation, "encrypt")
        self.assertEqual(result.data_size, len(test_data))
        self.assertGreater(result.execution_time, 0)
        self.assertTrue(result.success)


class TestSecurityAnalysis(unittest.TestCase):
    """Test cases for security analysis tools."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.validator = ComprehensiveSecurityValidator()
    
    def test_security_validator_initialization(self):
        """Test security validator initialization."""
        self.assertIsNotNone(self.validator.poly_analyzer)
        self.assertIsNotNone(self.validator.attack_analyzer)
        self.assertIsNotNone(self.validator.cpdpm)


class TestIntegration(unittest.TestCase):
    """Integration tests for complete CPDPM system."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.cpdpm = CPDPMHybrid()
        self.generator = SyntheticHealthcareGenerator(seed=42)
        self.key_manager = CPDPMKeyManager()
    
    def test_end_to_end_healthcare_scenario(self):
        """Test complete end-to-end healthcare encryption scenario."""
        # Generate synthetic patient data
        patient = self.generator.generate_patient_record()
        vitals = self.generator.generate_vital_signs(patient.patient_id, 2)
        
        # Create comprehensive healthcare record
        healthcare_record = {
            'patient': patient.__dict__,
            'vital_signs': [v.__dict__ for v in vitals]
        }
        
        healthcare_data = json.dumps(healthcare_record).encode('utf-8')
        
        # Generate context and password
        context = self.key_manager.derive_context_from_healthcare_data(
            patient.patient_id, "2024-01-15T10:00:00Z", "complete_record"
        )
        password = self.key_manager.generate_secure_password(24)
        
        # Encrypt
        encrypted_package = self.cpdpm.encrypt(healthcare_data, password, context)
        
        # Verify encryption
        self.assertIn('ciphertext', encrypted_package)
        self.assertIn('metadata', encrypted_package)
        self.assertEqual(
            encrypted_package['metadata']['algorithm'], 
            'CPDPM-AES256'
        )
        
        # Decrypt and verify
        decrypted_data = self.cpdpm.decrypt(encrypted_package, password)
        self.assertEqual(healthcare_data, decrypted_data)
        
        # Verify data integrity
        decrypted_record = json.loads(decrypted_data.decode('utf-8'))
        self.assertEqual(
            decrypted_record['patient']['patient_id'],
            patient.patient_id
        )
    
    def test_multiple_context_encryption(self):
        """Test encryption with different contexts."""
        test_data = b"Multi-context test data"
        password = "MultiContextPassword!"
        
        contexts = [
            "patient:001:vitals",
            "patient:002:vitals", 
            "patient:001:labs",
            "iomt:device:001"
        ]
        
        encrypted_packages = []
        
        # Encrypt with different contexts
        for context in contexts:
            encrypted = self.cpdpm.encrypt(test_data, password, context)
            encrypted_packages.append(encrypted)
        
        # All ciphertexts should be different due to context-aware keys
        ciphertexts = [pkg['ciphertext'] for pkg in encrypted_packages]
        self.assertEqual(len(set(ciphertexts)), len(ciphertexts))  # All unique
        
        # All should decrypt correctly
        for encrypted in encrypted_packages:
            decrypted = self.cpdpm.decrypt(encrypted, password)
            self.assertEqual(test_data, decrypted)


def run_comprehensive_tests():
    """Run all CPDPM tests and generate report."""
    
    print("🧪 Running Comprehensive CPDPM Test Suite")
    print("=" * 50)
    
    # Create test suite
    test_classes = [
        TestFiniteFieldPolynomial,
        TestCPDPMCore,
        TestCPDPMHybrid,
        TestCPDPMKeyManager,
        TestSyntheticHealthcareGenerator,
        TestPerformanceBenchmark,
        TestSecurityAnalysis,
        TestIntegration
    ]
    
    total_tests = 0
    total_failures = 0
    total_errors = 0
    
    for test_class in test_classes:
        print(f"\n📋 Running {test_class.__name__}...")
        
        suite = unittest.TestLoader().loadTestsFromTestCase(test_class)
        runner = unittest.TextTestRunner(verbosity=1)
        result = runner.run(suite)
        
        total_tests += result.testsRun
        total_failures += len(result.failures)
        total_errors += len(result.errors)
        
        if result.failures:
            print(f"  ❌ {len(result.failures)} failures")
            for test, traceback in result.failures:
                # Extract error message without backslashes in f-string
                error_msg = traceback.split('AssertionError: ')[-1].split('\n')[0]
                print(f"    - {test}: {error_msg}")
        
        if result.errors:
            print(f"  🚨 {len(result.errors)} errors")
            for test, traceback in result.errors:
                # Extract error message without backslashes in f-string
                error_msg = traceback.split('\n')[-2]
                print(f"    - {test}: {error_msg}")
        
        if not result.failures and not result.errors:
            print(f"  ✅ All {result.testsRun} tests passed")
    
    # Generate summary
    print(f"\n" + "=" * 50)
    print(f"🏆 CPDPM Test Suite Summary")
    print(f"Total Tests: {total_tests}")
    print(f"Passed: {total_tests - total_failures - total_errors}")
    print(f"Failed: {total_failures}")
    print(f"Errors: {total_errors}")
    
    success_rate = ((total_tests - total_failures - total_errors) / total_tests * 100) if total_tests > 0 else 0
    print(f"Success Rate: {success_rate:.1f}%")
    
    if total_failures == 0 and total_errors == 0:
        print(f"🎉 All tests passed! CPDPM implementation is ready.")
    else:
        print(f"⚠️  Some tests failed. Review implementation before deployment.")
    
    return {
        'total_tests': total_tests,
        'passed': total_tests - total_failures - total_errors,
        'failed': total_failures,
        'errors': total_errors,
        'success_rate': success_rate
    }


if __name__ == "__main__":
    # Run tests when executed directly
    test_results = run_comprehensive_tests()