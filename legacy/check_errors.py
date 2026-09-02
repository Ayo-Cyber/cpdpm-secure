#!/usr/bin/env python3
"""
CPDPM Error Check Script

Quick validation script to check for common errors and dependencies.
Run this before executing the full test suite.

Author: CPDPM Research Team
"""

import sys
import importlib
import os

def check_dependencies():
    """Check if all required dependencies are available."""
    
    print("🔍 Checking CPDPM Dependencies...")
    
    required_packages = [
        ('numpy', 'NumPy'),
        ('pandas', 'Pandas'),
        ('matplotlib', 'Matplotlib'),
        ('seaborn', 'Seaborn'),
        ('cryptography', 'Cryptography'),
        ('scipy', 'SciPy'),
        ('psutil', 'PSUtil'),
        ('tqdm', 'TQDM')
    ]
    
    missing_packages = []
    
    for package, name in required_packages:
        try:
            importlib.import_module(package)
            print(f"  ✅ {name}")
        except ImportError:
            print(f"  ❌ {name} - MISSING")
            missing_packages.append(package)
    
    if missing_packages:
        print(f"\n⚠️ Missing packages: {', '.join(missing_packages)}")
        print("Install with: pip install -r requirements.txt")
        return False
    else:
        print("\n✅ All dependencies available!")
        return True

def check_module_imports():
    """Check if CPDPM modules can be imported."""
    
    print("\n🔍 Checking CPDPM Module Imports...")
    
    # Add src to Python path
    src_path = os.path.join(os.path.dirname(__file__), '..', 'src')
    if src_path not in sys.path:
        sys.path.insert(0, os.path.abspath(src_path))
    
    modules_to_test = [
        ('cpdpm_core', 'CPDPM Core'),
        ('cpdpm_hybrid', 'CPDPM Hybrid'),
        ('synthetic_data', 'Synthetic Data'),
        ('benchmarks', 'Benchmarks'),
        ('security_analysis', 'Security Analysis')
    ]
    
    import_errors = []
    
    for module_name, display_name in modules_to_test:
        try:
            module = importlib.import_module(module_name)
            print(f"  ✅ {display_name}")
        except ImportError as e:
            print(f"  ❌ {display_name} - ERROR: {str(e)}")
            import_errors.append((module_name, str(e)))
        except Exception as e:
            print(f"  ⚠️ {display_name} - WARNING: {str(e)}")
    
    if import_errors:
        print(f"\n❌ Import errors found:")
        for module, error in import_errors:
            print(f"  - {module}: {error}")
        return False
    else:
        print("\n✅ All CPDPM modules import successfully!")
        return True

def check_basic_functionality():
    """Test basic CPDPM functionality."""
    
    print("\n🔍 Testing Basic CPDPM Functionality...")
    
    try:
        # Test polynomial operations
        from cpdpm_core import FiniteFieldPolynomial
        poly_engine = FiniteFieldPolynomial()
        key = poly_engine.generate_polynomial_key(degree=3, seed=42)
        test_data = b"Test data"
        transformed = poly_engine.polynomial_transform(test_data, key)
        recovered = poly_engine.polynomial_inverse_transform(transformed, key)
        
        if test_data == recovered:
            print("  ✅ Polynomial transformations working")
        else:
            print("  ❌ Polynomial transformation failed")
            return False
        
        # Test CPDPM encryption
        from cpdpm_hybrid import CPDPMHybrid
        cpdpm = CPDPMHybrid()
        encrypted = cpdpm.encrypt(test_data, "password123")
        decrypted = cpdpm.decrypt(encrypted, "password123")
        
        if test_data == decrypted:
            print("  ✅ CPDPM encryption/decryption working")
        else:
            print("  ❌ CPDPM encryption failed")
            return False
        
        # Test synthetic data
        from synthetic_data import SyntheticHealthcareGenerator
        generator = SyntheticHealthcareGenerator(seed=42)
        patient = generator.generate_patient_record()
        
        if patient.patient_id.startswith('PAT-'):
            print("  ✅ Synthetic data generation working")
        else:
            print("  ❌ Synthetic data generation failed")
            return False
        
        print("\n✅ All basic functionality tests passed!")
        return True
        
    except Exception as e:
        print(f"  ❌ Functionality test failed: {str(e)}")
        return False

def check_file_structure():
    """Check if all required files exist."""
    
    print("\n🔍 Checking File Structure...")
    
    required_files = [
        'src/cpdpm_core.py',
        'src/cpdpm_hybrid.py', 
        'src/synthetic_data.py',
        'src/benchmarks.py',
        'src/security_analysis.py',
        'src/__init__.py',
        'tests/test_cpdpm_comprehensive.py',
        'tests/quick_test.py',
        'requirements.txt',
        'README.md'
    ]
    
    missing_files = []
    
    for file_path in required_files:
        full_path = os.path.join(os.path.dirname(__file__), '..', file_path)
        if os.path.exists(full_path):
            print(f"  ✅ {file_path}")
        else:
            print(f"  ❌ {file_path} - MISSING")
            missing_files.append(file_path)
    
    if missing_files:
        print(f"\n⚠️ Missing files: {missing_files}")
        return False
    else:
        print("\n✅ All required files present!")
        return True

def main():
    """Run comprehensive error checking."""
    
    print("🚀 CPDPM Error Check & Validation")
    print("=" * 50)
    
    checks = [
        ("File Structure", check_file_structure),
        ("Dependencies", check_dependencies),
        ("Module Imports", check_module_imports),
        ("Basic Functionality", check_basic_functionality)
    ]
    
    all_passed = True
    
    for check_name, check_func in checks:
        try:
            result = check_func()
            if not result:
                all_passed = False
        except Exception as e:
            print(f"❌ {check_name} check failed with error: {e}")
            all_passed = False
    
    print("\n" + "=" * 50)
    if all_passed:
        print("🎉 All checks passed! CPDPM system is ready to run.")
        print("\nNext steps:")
        print("1. Run: python tests/quick_test.py")
        print("2. Run: python tests/test_cpdpm_comprehensive.py")
        print("3. Open: jupyter notebook notebooks/CPDPM_Demo_Healthcare_Encryption.ipynb")
    else:
        print("⚠️ Some checks failed. Please fix the issues above before proceeding.")
        print("\nCommon fixes:")
        print("1. Install dependencies: pip install -r requirements.txt")
        print("2. Check Python path: export PYTHONPATH=$PYTHONPATH:$(pwd)/src")
        print("3. Verify file structure and permissions")
    
    return all_passed

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)