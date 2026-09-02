"""
Quick Test Runner for CPDPM Development

This module provides a simplified test runner for quick validation
during CPDPM development and debugging.

Author: CPDPM Research Team
"""

import sys
import os
import traceback

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

def quick_test_cpdpm():
    """Run quick validation tests for CPDPM components."""
    
    print("🚀 CPDPM Quick Test Suite")
    print("=" * 30)
    
    tests_passed = 0
    tests_total = 0
    
    # Test 1: Import all modules
    print("\n1️⃣ Testing module imports...")
    tests_total += 1
    try:
        from cpdpm_core import CPDPMCore, FiniteFieldPolynomial
        from cpdpm_hybrid import CPDPMHybrid, CPDPMKeyManager
        from synthetic_data import SyntheticHealthcareGenerator
        from benchmarks import PerformanceBenchmark
        from security_analysis import ComprehensiveSecurityValidator
        print("   ✅ All modules imported successfully")
        tests_passed += 1
    except Exception as e:
        print(f"   ❌ Import failed: {e}")
    
    # Test 2: Basic polynomial operations
    print("\n2️⃣ Testing polynomial operations...")
    tests_total += 1
    try:
        poly_engine = FiniteFieldPolynomial()
        key = poly_engine.generate_polynomial_key(degree=3, seed=42)
        test_data = b"Test polynomial"
        
        transformed = poly_engine.polynomial_transform(test_data, key)
        recovered = poly_engine.polynomial_inverse_transform(transformed, key)
        
        assert test_data == recovered, "Polynomial transformation not invertible"
        print("   ✅ Polynomial operations working")
        tests_passed += 1
    except Exception as e:
        print(f"   ❌ Polynomial test failed: {e}")
    
    # Test 3: CPDPM encryption/decryption
    print("\n3️⃣ Testing CPDPM encryption...")
    tests_total += 1
    try:
        cpdpm = CPDPMHybrid()
        test_data = b"Healthcare test data"
        password = "TestPassword123!"
        
        encrypted = cpdpm.encrypt(test_data, password)
        decrypted = cpdpm.decrypt(encrypted, password)
        
        assert test_data == decrypted, "CPDPM encryption not working"
        print("   ✅ CPDPM encryption/decryption working")
        tests_passed += 1
    except Exception as e:
        print(f"   ❌ CPDPM encryption test failed: {e}")
    
    # Test 4: Synthetic data generation
    print("\n4️⃣ Testing synthetic data generation...")
    tests_total += 1
    try:
        generator = SyntheticHealthcareGenerator(seed=42)
        patient = generator.generate_patient_record()
        vitals = generator.generate_vital_signs(patient.patient_id, 2)
        
        assert len(vitals) == 2, "Wrong number of vital signs generated"
        assert patient.patient_id.startswith('PAT-'), "Invalid patient ID format"
        print("   ✅ Synthetic data generation working")
        tests_passed += 1
    except Exception as e:
        print(f"   ❌ Synthetic data test failed: {e}")
    
    # Test 5: Key management
    print("\n5️⃣ Testing key management...")
    tests_total += 1
    try:
        key_manager = CPDPMKeyManager()
        password = key_manager.generate_secure_password(16)
        context = key_manager.derive_context_from_healthcare_data(
            "TEST-001", "2024-01-01", "vitals"
        )
        
        assert len(password) == 16, "Wrong password length"
        assert "patient:TEST-001" in context, "Invalid context format"
        print("   ✅ Key management working")
        tests_passed += 1
    except Exception as e:
        print(f"   ❌ Key management test failed: {e}")
    
    # Test 6: Performance benchmark initialization
    print("\n6️⃣ Testing benchmark initialization...")
    tests_total += 1
    try:
        benchmark = PerformanceBenchmark()
        test_data = b"Benchmark test"
        result = benchmark.benchmark_cpdpm_encryption(test_data)
        
        assert result.success, "Benchmark failed"
        assert result.execution_time > 0, "Invalid execution time"
        print("   ✅ Performance benchmark working")
        tests_passed += 1
    except Exception as e:
        print(f"   ❌ Benchmark test failed: {e}")
    
    # Test 7: Security analysis initialization
    print("\n7️⃣ Testing security analysis...")
    tests_total += 1
    try:
        validator = ComprehensiveSecurityValidator()
        # Just test initialization for now
        assert validator.poly_analyzer is not None, "Security analyzer not initialized"
        print("   ✅ Security analysis initialization working")
        tests_passed += 1
    except Exception as e:
        print(f"   ❌ Security analysis test failed: {e}")
    
    # Summary
    print(f"\n" + "=" * 30)
    print(f"🏆 Quick Test Results:")
    print(f"   Passed: {tests_passed}/{tests_total}")
    print(f"   Success Rate: {tests_passed/tests_total*100:.1f}%")
    
    if tests_passed == tests_total:
        print("   🎉 All quick tests passed!")
        return True
    else:
        print("   ⚠️ Some tests failed - check implementation")
        return False


def test_healthcare_scenario():
    """Test a complete healthcare encryption scenario."""
    
    print("\n🏥 Healthcare Scenario Test")
    print("-" * 30)
    
    try:
        # Import modules
        from cpdpm_hybrid import CPDPMHybrid
        from synthetic_data import SyntheticHealthcareGenerator
        import json
        
        # Initialize components
        cpdpm = CPDPMHybrid()
        generator = SyntheticHealthcareGenerator(seed=42)
        
        # Generate patient data
        patient = generator.generate_patient_record()
        vitals = generator.generate_vital_signs(patient.patient_id, 2)
        
        # Create healthcare record
        healthcare_record = {
            'patient': {
                'id': patient.patient_id,
                'age': patient.age,
                'gender': patient.gender
            },
            'vitals': [{
                'heart_rate': v.heart_rate_bpm,
                'blood_pressure': f"{v.blood_pressure_systolic}/{v.blood_pressure_diastolic}",
                'temperature': v.temperature_celsius
            } for v in vitals]
        }
        
        healthcare_data = json.dumps(healthcare_record, indent=2).encode('utf-8')
        
        print(f"Generated healthcare record: {len(healthcare_data)} bytes")
        
        # Encrypt with CPDPM
        password = "HealthcareDemo2024!"
        context = f"patient:{patient.patient_id}:demo"
        
        encrypted = cpdpm.encrypt(healthcare_data, password, context)
        print(f"Encrypted with CPDPM: {len(encrypted['ciphertext'])} chars")
        
        # Decrypt and verify
        decrypted = cpdpm.decrypt(encrypted, password)
        
        if healthcare_data == decrypted:
            print("✅ Healthcare scenario test PASSED")
            return True
        else:
            print("❌ Healthcare scenario test FAILED - data mismatch")
            return False
            
    except Exception as e:
        print(f"❌ Healthcare scenario test FAILED: {e}")
        traceback.print_exc()
        return False


if __name__ == "__main__":
    # Run quick tests
    quick_success = quick_test_cpdpm()
    
    # Run healthcare scenario test
    scenario_success = test_healthcare_scenario()
    
    # Overall result
    if quick_success and scenario_success:
        print("\n🎯 All tests completed successfully!")
        print("CPDPM system is ready for demonstration.")
        sys.exit(0)
    else:
        print("\n💥 Some tests failed!")
        print("Please review implementation before proceeding.")
        sys.exit(1)