"""
Security Analysis Tools for CPDPM

This module provides comprehensive security analysis capabilities for the
Contextual Polynomial-based Data Protection Model, including polynomial
complexity analysis, resistance testing, and cryptographic validation.

Author: CPDPM Research Team
"""

import numpy as np
import random
import hashlib
import itertools
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
import time
import matplotlib.pyplot as plt
import seaborn as sns
from scipy import stats
import json
import base64

from cpdpm_core import CPDPMCore, PolynomialKey, FiniteFieldPolynomial
from cpdpm_hybrid import CPDPMHybrid
from synthetic_data import SyntheticHealthcareGenerator


@dataclass
class SecurityTestResult:
    """Results from a security analysis test."""
    test_name: str
    test_type: str
    polynomial_degree: int
    success: bool
    security_score: float
    time_taken: float
    details: Dict[str, Any]
    recommendations: List[str]


@dataclass
class PolynomialComplexityAnalysis:
    """Analysis of polynomial mathematical complexity."""
    degree: int
    coefficient_entropy: float
    exponent_variance: float
    prime_modulus: int
    invertibility_score: float
    complexity_rating: str
    estimated_attack_time: float


class PolynomialSecurityAnalyzer:
    """
    Advanced security analysis for polynomial transformations in CPDPM.
    """
    
    def __init__(self):
        """Initialize security analyzer."""
        self.cpdpm_core = CPDPMCore()
        self.poly_engine = FiniteFieldPolynomial()
        
    def analyze_polynomial_complexity(self, key: PolynomialKey) -> PolynomialComplexityAnalysis:
        """
        Analyze the mathematical complexity of a polynomial key.
        
        Args:
            key: Polynomial key to analyze
            
        Returns:
            Comprehensive complexity analysis
        """
        # Calculate coefficient entropy
        coeff_array = np.array(key.coefficients)
        coeff_entropy = stats.entropy(coeff_array / np.sum(coeff_array))
        
        # Calculate exponent variance
        exp_variance = np.var(key.exponents)
        
        # Test invertibility across sample space
        invertibility_score = self._test_polynomial_invertibility(key)
        
        # Estimate computational complexity for brute force
        max_coeff = max(key.coefficients)
        max_exp = max(key.exponents)
        
        # Rough estimate: complexity ~ degree * max_exp * log(max_coeff) * prime_size
        base_complexity = key.degree * max_exp * np.log2(max_coeff) * np.log2(key.prime_modulus)
        
        # Estimate attack time (very rough approximation)
        # Assume 10^9 operations per second for polynomial evaluation
        estimated_ops = key.prime_modulus ** min(key.degree, 3)  # Limited search space
        estimated_time = estimated_ops / 1e9  # seconds
        
        # Determine complexity rating
        if base_complexity > 1000 and invertibility_score > 0.95:
            rating = "High"
        elif base_complexity > 500 and invertibility_score > 0.90:
            rating = "Medium-High"
        elif base_complexity > 200 and invertibility_score > 0.85:
            rating = "Medium"
        else:
            rating = "Low"
        
        return PolynomialComplexityAnalysis(
            degree=key.degree,
            coefficient_entropy=coeff_entropy,
            exponent_variance=exp_variance,
            prime_modulus=key.prime_modulus,
            invertibility_score=invertibility_score,
            complexity_rating=rating,
            estimated_attack_time=estimated_time
        )
    
    def _test_polynomial_invertibility(self, key: PolynomialKey, sample_size: int = 1000) -> float:
        """
        Test how well polynomial transformations can be inverted.
        
        Args:
            key: Polynomial key to test
            sample_size: Number of random inputs to test
            
        Returns:
            Invertibility score (0.0 to 1.0)
        """
        correct_inversions = 0
        
        for _ in range(sample_size):
            # Generate random test input
            test_input = bytes([random.randint(0, 255)])
            
            try:
                # Apply transformation and inverse
                transformed = self.poly_engine.polynomial_transform(test_input, key)
                recovered = self.poly_engine.polynomial_inverse_transform(transformed, key)
                
                if test_input == recovered:
                    correct_inversions += 1
            except Exception:
                # Inversion failed
                pass
        
        return correct_inversions / sample_size
    
    def test_polynomial_randomness(self, key: PolynomialKey, sample_size: int = 10000) -> Dict[str, float]:
        """
        Test the randomness properties of polynomial transformations.
        
        Args:
            key: Polynomial key to test
            sample_size: Number of samples for statistical tests
            
        Returns:
            Randomness test results
        """
        # Generate transformed samples
        inputs = [bytes([i % 256]) for i in range(min(sample_size, 256))]
        outputs = []
        
        for input_byte in inputs:
            try:
                transformed = self.poly_engine.polynomial_transform(input_byte, key)
                outputs.extend(list(transformed))
            except Exception:
                continue
        
        if not outputs:
            return {'error': 'No valid transformations generated'}
        
        outputs_array = np.array(outputs)
        
        # Statistical tests
        results = {}
        
        # Frequency test (chi-square)
        expected_freq = len(outputs) / 256
        observed_freq = np.bincount(outputs_array, minlength=256)
        chi_square_stat = np.sum((observed_freq - expected_freq) ** 2 / expected_freq)
        chi_square_p_value = 1 - stats.chi2.cdf(chi_square_stat, 255)
        
        results['frequency_test_p_value'] = chi_square_p_value
        results['frequency_test_pass'] = chi_square_p_value > 0.01
        
        # Runs test (test for independence)
        median = np.median(outputs_array)
        runs, n1, n2 = self._calculate_runs(outputs_array, median)
        
        if n1 > 10 and n2 > 10:
            expected_runs = (2 * n1 * n2) / (n1 + n2) + 1
            variance_runs = (2 * n1 * n2 * (2 * n1 * n2 - n1 - n2)) / ((n1 + n2) ** 2 * (n1 + n2 - 1))
            
            if variance_runs > 0:
                z_stat = (runs - expected_runs) / np.sqrt(variance_runs)
                runs_p_value = 2 * (1 - stats.norm.cdf(abs(z_stat)))
                
                results['runs_test_p_value'] = runs_p_value
                results['runs_test_pass'] = runs_p_value > 0.01
            else:
                results['runs_test_error'] = 'Insufficient variance for runs test'
        else:
            results['runs_test_error'] = 'Insufficient data for runs test'
        
        # Entropy estimation
        _, counts = np.unique(outputs_array, return_counts=True)
        probabilities = counts / len(outputs_array)
        entropy = -np.sum(probabilities * np.log2(probabilities))
        max_entropy = 8.0  # 8 bits per byte
        
        results['entropy_bits'] = entropy
        results['entropy_ratio'] = entropy / max_entropy
        results['high_entropy'] = entropy > 7.0
        
        return results
    
    def _calculate_runs(self, sequence: np.ndarray, median: float) -> Tuple[int, int, int]:
        """Calculate runs for runs test."""
        binary_seq = sequence > median
        runs = 1
        n1 = np.sum(binary_seq)
        n2 = len(binary_seq) - n1
        
        for i in range(1, len(binary_seq)):
            if binary_seq[i] != binary_seq[i-1]:
                runs += 1
        
        return runs, n1, n2
    
    def test_key_sensitivity(self, base_key: PolynomialKey, num_variations: int = 100) -> Dict[str, float]:
        """
        Test sensitivity of polynomial transformations to key changes.
        
        Args:
            base_key: Original polynomial key
            num_variations: Number of key variations to test
            
        Returns:
            Key sensitivity analysis results
        """
        test_data = b"Test data for key sensitivity analysis."
        base_transformed = self.poly_engine.polynomial_transform(test_data, base_key)
        
        bit_differences = []
        
        for _ in range(num_variations):
            # Create slight variation of the key
            varied_key = self._create_key_variation(base_key)
            
            # Transform with varied key
            varied_transformed = self.poly_engine.polynomial_transform(test_data, varied_key)
            
            # Calculate bit differences
            if len(base_transformed) == len(varied_transformed):
                different_bits = 0
                total_bits = len(base_transformed) * 8
                
                for base_byte, var_byte in zip(base_transformed, varied_transformed):
                    xor_result = base_byte ^ var_byte
                    different_bits += bin(xor_result).count('1')
                
                change_percentage = (different_bits / total_bits) * 100
                bit_differences.append(change_percentage)
        
        if bit_differences:
            return {
                'average_bit_change': np.mean(bit_differences),
                'min_bit_change': np.min(bit_differences),
                'max_bit_change': np.max(bit_differences),
                'std_bit_change': np.std(bit_differences),
                'high_sensitivity': np.mean(bit_differences) > 30.0,
                'sensitivity_score': min(100.0, np.mean(bit_differences) * 2)  # Scale to 100
            }
        else:
            return {'error': 'No valid key sensitivity measurements'}
    
    def _create_key_variation(self, base_key: PolynomialKey) -> PolynomialKey:
        """Create a slightly modified version of a polynomial key."""
        varied_coefficients = base_key.coefficients.copy()
        varied_exponents = base_key.exponents.copy()
        
        # Modify one coefficient slightly
        if varied_coefficients:
            idx = random.randint(0, len(varied_coefficients) - 1)
            variation = random.randint(-100, 100)
            varied_coefficients[idx] = max(1, varied_coefficients[idx] + variation)
        
        # Occasionally modify an exponent
        if random.random() < 0.3 and varied_exponents:
            idx = random.randint(0, len(varied_exponents) - 1)
            varied_exponents[idx] = max(0, varied_exponents[idx] + random.choice([-1, 1]))
        
        return PolynomialKey(
            coefficients=varied_coefficients,
            exponents=varied_exponents,
            prime_modulus=base_key.prime_modulus,
            degree=base_key.degree
        )


class AttackResistanceAnalyzer:
    """
    Analyzer for testing resistance against various cryptographic attacks.
    """
    
    def __init__(self):
        """Initialize attack resistance analyzer."""
        self.cpdpm = CPDPMHybrid()
        self.poly_analyzer = PolynomialSecurityAnalyzer()
    
    def test_brute_force_resistance(self, 
                                  ciphertext_sample: dict,
                                  known_plaintext: bytes,
                                  max_attempts: int = 10000) -> SecurityTestResult:
        """
        Test resistance to brute force password attacks.
        
        Args:
            ciphertext_sample: Encrypted data sample
            known_plaintext: Known plaintext for verification
            max_attempts: Maximum brute force attempts
            
        Returns:
            Brute force resistance test results
        """
        start_time = time.time()
        
        # Generate common passwords to test
        common_passwords = self._generate_common_passwords(max_attempts)
        
        successful_cracks = 0
        attempts = 0
        
        for password in common_passwords:
            attempts += 1
            try:
                decrypted = self.cpdpm.decrypt(ciphertext_sample, password)
                if decrypted == known_plaintext:
                    successful_cracks += 1
                    break
            except Exception:
                # Decryption failed, continue
                continue
        
        test_time = time.time() - start_time
        
        # Calculate security score (lower is better for attacker)
        resistance_score = max(0, 100 - (successful_cracks / attempts * 100))
        
        details = {
            'attempts_made': attempts,
            'successful_cracks': successful_cracks,
            'resistance_percentage': resistance_score,
            'time_per_attempt': test_time / attempts if attempts > 0 else 0
        }
        
        recommendations = []
        if successful_cracks > 0:
            recommendations.append("Use stronger, more complex passwords")
            recommendations.append("Implement key derivation function with higher iterations")
        if resistance_score < 90:
            recommendations.append("Consider increasing polynomial complexity")
        
        return SecurityTestResult(
            test_name="Brute Force Password Attack",
            test_type="Attack Resistance",
            polynomial_degree=5,  # Default assumption
            success=successful_cracks == 0,
            security_score=resistance_score,
            time_taken=test_time,
            details=details,
            recommendations=recommendations
        )
    
    def test_known_plaintext_attack(self,
                                  plaintext_ciphertext_pairs: List[Tuple[bytes, dict]],
                                  target_ciphertext: dict) -> SecurityTestResult:
        """
        Test resistance to known plaintext attacks.
        
        Args:
            plaintext_ciphertext_pairs: List of (plaintext, ciphertext) pairs
            target_ciphertext: Target ciphertext to attempt to break
            
        Returns:
            Known plaintext attack resistance results
        """
        start_time = time.time()
        
        # Analyze patterns in known pairs
        patterns = self._analyze_plaintext_patterns(plaintext_ciphertext_pairs)
        
        # Attempt to derive key information
        key_recovery_attempts = 0
        pattern_matches = 0
        
        for plaintext, ciphertext in plaintext_ciphertext_pairs:
            key_recovery_attempts += 1
            
            # Look for exploitable patterns
            if self._has_exploitable_pattern(plaintext, ciphertext):
                pattern_matches += 1
        
        test_time = time.time() - start_time
        
        # Calculate resistance score
        pattern_ratio = pattern_matches / len(plaintext_ciphertext_pairs) if plaintext_ciphertext_pairs else 0
        resistance_score = max(0, 100 - (pattern_ratio * 80))  # Patterns reduce security
        
        details = {
            'plaintext_pairs_analyzed': len(plaintext_ciphertext_pairs),
            'exploitable_patterns_found': pattern_matches,
            'pattern_exploitation_ratio': pattern_ratio,
            'key_recovery_success': False,  # Simplified for this implementation
            'analysis_complexity': patterns.get('complexity_score', 0)
        }
        
        recommendations = []
        if pattern_matches > len(plaintext_ciphertext_pairs) * 0.1:
            recommendations.append("Increase contextual randomization in polynomial keys")
            recommendations.append("Use different polynomial parameters for different contexts")
        
        return SecurityTestResult(
            test_name="Known Plaintext Attack",
            test_type="Attack Resistance",
            polynomial_degree=5,
            success=pattern_matches < len(plaintext_ciphertext_pairs) * 0.05,
            security_score=resistance_score,
            time_taken=test_time,
            details=details,
            recommendations=recommendations
        )
    
    def test_differential_cryptanalysis(self, 
                                     sample_size: int = 1000) -> SecurityTestResult:
        """
        Test resistance to differential cryptanalysis.
        
        Args:
            sample_size: Number of plaintext pairs to analyze
            
        Returns:
            Differential cryptanalysis resistance results
        """
        start_time = time.time()
        
        password = "test_differential_analysis"
        context = "differential_test"
        
        # Generate pairs with small differences
        differential_pairs = []
        high_probability_differentials = 0
        
        for _ in range(sample_size):
            # Generate random plaintext
            plaintext1 = bytes([random.randint(0, 255) for _ in range(16)])
            
            # Create plaintext with 1-bit difference
            plaintext2 = bytearray(plaintext1)
            byte_idx = random.randint(0, len(plaintext2) - 1)
            bit_idx = random.randint(0, 7)
            plaintext2[byte_idx] ^= (1 << bit_idx)
            plaintext2 = bytes(plaintext2)
            
            # Encrypt both
            try:
                cipher1 = self.cpdpm.encrypt(plaintext1, password, context)
                cipher2 = self.cpdpm.encrypt(plaintext2, password, context)
                
                # Analyze output difference
                output_diff = self._calculate_output_difference(cipher1, cipher2)
                differential_pairs.append(output_diff)
                
                # Check for high-probability differentials
                if output_diff > 0.7:  # Threshold for concern
                    high_probability_differentials += 1
                    
            except Exception:
                continue
        
        test_time = time.time() - start_time
        
        # Calculate resistance score
        if differential_pairs:
            avg_differential = np.mean(differential_pairs)
            resistance_score = max(0, 100 - (high_probability_differentials / len(differential_pairs) * 100))
        else:
            avg_differential = 0
            resistance_score = 0
        
        details = {
            'differential_pairs_tested': len(differential_pairs),
            'high_probability_differentials': high_probability_differentials,
            'average_output_differential': avg_differential,
            'differential_uniformity': np.std(differential_pairs) if differential_pairs else 0
        }
        
        recommendations = []
        if high_probability_differentials > sample_size * 0.01:
            recommendations.append("Review polynomial construction for differential properties")
            recommendations.append("Consider adding more nonlinear components")
        
        return SecurityTestResult(
            test_name="Differential Cryptanalysis",
            test_type="Attack Resistance", 
            polynomial_degree=5,
            success=high_probability_differentials < sample_size * 0.01,
            security_score=resistance_score,
            time_taken=test_time,
            details=details,
            recommendations=recommendations
        )
    
    def _generate_common_passwords(self, count: int) -> List[str]:
        """Generate list of common passwords for brute force testing."""
        base_passwords = [
            "password", "123456", "password123", "admin", "letmein",
            "qwerty", "welcome", "monkey", "dragon", "master",
            "shadow", "test", "guest", "user", "root"
        ]
        
        # Add variations
        passwords = []
        for base in base_passwords:
            passwords.extend([
                base,
                base + "123",
                base + "1",
                base.capitalize(),
                base.upper(),
                "123" + base,
                base + "!",
                base + "@",
                base + "2023",
                base + "2024"
            ])
        
        # Add random passwords
        while len(passwords) < count:
            length = random.randint(4, 12)
            chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
            random_pass = ''.join(random.choice(chars) for _ in range(length))
            passwords.append(random_pass)
        
        return passwords[:count]
    
    def _analyze_plaintext_patterns(self, pairs: List[Tuple[bytes, dict]]) -> Dict[str, Any]:
        """Analyze patterns in plaintext-ciphertext pairs."""
        if not pairs:
            return {'complexity_score': 0}
        
        # Simple pattern analysis
        plaintext_lengths = [len(p[0]) for p in pairs]
        ciphertext_lengths = [len(p[1].get('ciphertext', '')) for p in pairs]
        
        length_correlation = np.corrcoef(plaintext_lengths, ciphertext_lengths)[0, 1] if len(pairs) > 1 else 0
        
        return {
            'pair_count': len(pairs),
            'avg_plaintext_length': np.mean(plaintext_lengths),
            'avg_ciphertext_length': np.mean(ciphertext_lengths),
            'length_correlation': length_correlation,
            'complexity_score': abs(length_correlation) * 100  # Simplified metric
        }
    
    def _has_exploitable_pattern(self, plaintext: bytes, ciphertext: dict) -> bool:
        """Check if a plaintext-ciphertext pair has exploitable patterns."""
        # Simplified pattern detection
        plaintext_entropy = self._calculate_entropy(plaintext)
        
        # Low entropy plaintext might reveal patterns
        return plaintext_entropy < 4.0  # Threshold for low entropy
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = np.bincount(list(data), minlength=256)
        probabilities = byte_counts[byte_counts > 0] / len(data)
        
        # Calculate entropy
        entropy = -np.sum(probabilities * np.log2(probabilities))
        return entropy
    
    def _calculate_output_difference(self, cipher1: dict, cipher2: dict) -> float:
        """Calculate normalized difference between two ciphertexts."""
        try:
            ctext1 = base64.b64decode(cipher1['ciphertext'])
            ctext2 = base64.b64decode(cipher2['ciphertext'])
            
            if len(ctext1) != len(ctext2):
                return 1.0  # Maximum difference
            
            different_bytes = sum(b1 != b2 for b1, b2 in zip(ctext1, ctext2))
            return different_bytes / len(ctext1)
        except Exception:
            return 0.0


class ComprehensiveSecurityValidator:
    """
    Comprehensive security validation suite for CPDPM.
    """
    
    def __init__(self):
        """Initialize comprehensive validator."""
        self.poly_analyzer = PolynomialSecurityAnalyzer()
        self.attack_analyzer = AttackResistanceAnalyzer()
        self.cpdpm = CPDPMHybrid()
    
    def run_full_security_analysis(self, 
                                 polynomial_degrees: List[int] = None,
                                 test_iterations: int = 100) -> Dict[str, Any]:
        """
        Run comprehensive security analysis of CPDPM.
        
        Args:
            polynomial_degrees: List of polynomial degrees to test
            test_iterations: Number of iterations for statistical tests
            
        Returns:
            Complete security analysis results
        """
        if polynomial_degrees is None:
            polynomial_degrees = [3, 5, 7, 9]
        
        print("Running comprehensive CPDPM security analysis...")
        
        results = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'polynomial_analyses': {},
            'attack_resistance_tests': [],
            'overall_security_assessment': {},
            'recommendations': []
        }
        
        # Test each polynomial degree
        for degree in polynomial_degrees:
            print(f"  Analyzing polynomial degree {degree}...")
            
            # Generate test key
            key = self.cpdpm.cpdpm_core.poly_engine.generate_polynomial_key(degree)
            
            # Polynomial complexity analysis
            complexity_analysis = self.poly_analyzer.analyze_polynomial_complexity(key)
            
            # Randomness tests
            randomness_tests = self.poly_analyzer.test_polynomial_randomness(key, test_iterations)
            
            # Key sensitivity tests
            sensitivity_tests = self.poly_analyzer.test_key_sensitivity(key, test_iterations // 10)
            
            results['polynomial_analyses'][f'degree_{degree}'] = {
                'complexity_analysis': asdict(complexity_analysis),
                'randomness_tests': randomness_tests,
                'sensitivity_tests': sensitivity_tests
            }
        
        # Attack resistance tests
        print("  Testing attack resistance...")
        
        # Generate test data
        generator = SyntheticHealthcareGenerator(seed=42)
        test_data = generator.generate_hipaa_compliant_sample()
        password = "TestPassword123!"
        context = "security_analysis"
        
        # Encrypt test data
        encrypted_sample = self.cpdpm.encrypt(test_data, password, context)
        
        # Brute force test
        brute_force_result = self.attack_analyzer.test_brute_force_resistance(
            encrypted_sample, test_data, max_attempts=1000
        )
        results['attack_resistance_tests'].append(asdict(brute_force_result))
        
        # Differential cryptanalysis test
        differential_result = self.attack_analyzer.test_differential_cryptanalysis(
            sample_size=test_iterations
        )
        results['attack_resistance_tests'].append(asdict(differential_result))
        
        # Generate overall assessment
        results['overall_security_assessment'] = self._generate_overall_assessment(results)
        
        print("Security analysis completed!")
        return results
    
    def _generate_overall_assessment(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate overall security assessment from analysis results."""
        
        # Collect security scores
        security_scores = []
        complexity_ratings = []
        
        # Analyze polynomial results
        for degree_key, poly_analysis in analysis_results['polynomial_analyses'].items():
            complexity = poly_analysis['complexity_analysis']
            complexity_ratings.append(complexity['complexity_rating'])
            
            # Convert complexity rating to numeric score
            rating_scores = {'Low': 25, 'Medium': 50, 'Medium-High': 75, 'High': 100}
            security_scores.append(rating_scores.get(complexity['complexity_rating'], 50))
        
        # Analyze attack resistance
        for attack_test in analysis_results['attack_resistance_tests']:
            security_scores.append(attack_test['security_score'])
        
        # Calculate overall metrics
        avg_security_score = np.mean(security_scores) if security_scores else 0
        min_security_score = np.min(security_scores) if security_scores else 0
        
        # Determine overall security level
        if avg_security_score >= 90 and min_security_score >= 80:
            overall_level = "High"
        elif avg_security_score >= 75 and min_security_score >= 65:
            overall_level = "Medium-High"
        elif avg_security_score >= 60 and min_security_score >= 50:
            overall_level = "Medium"
        else:
            overall_level = "Low"
        
        # Generate recommendations
        recommendations = []
        
        if 'Low' in complexity_ratings:
            recommendations.append("Consider using higher polynomial degrees for better security")
        
        if avg_security_score < 80:
            recommendations.append("Strengthen password requirements and key derivation")
        
        if min_security_score < 70:
            recommendations.append("Review polynomial construction for weakest configurations")
        
        recommendations.append("Regular security audits recommended")
        recommendations.append("Monitor for new cryptanalytic attacks on polynomial systems")
        
        return {
            'overall_security_level': overall_level,
            'average_security_score': avg_security_score,
            'minimum_security_score': min_security_score,
            'security_score_distribution': {
                'mean': float(np.mean(security_scores)),
                'std': float(np.std(security_scores)),
                'min': float(np.min(security_scores)),
                'max': float(np.max(security_scores))
            },
            'complexity_distribution': {
                'high': complexity_ratings.count('High'),
                'medium_high': complexity_ratings.count('Medium-High'),
                'medium': complexity_ratings.count('Medium'),
                'low': complexity_ratings.count('Low')
            },
            'recommendations': recommendations
        }
    
    def save_security_report(self, analysis_results: Dict[str, Any], output_file: str):
        """Save security analysis results to JSON file."""
        with open(output_file, 'w') as f:
            json.dump(analysis_results, f, indent=2, default=str)
        
        print(f"Security analysis report saved to {output_file}")
    
    def generate_security_visualization(self, 
                                      analysis_results: Dict[str, Any],
                                      output_dir: str):
        """Generate security analysis visualizations."""
        import os
        os.makedirs(output_dir, exist_ok=True)
        
        # Set up plotting
        plt.style.use('default')
        sns.set_palette("viridis")
        
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('CPDPM Security Analysis Results', fontsize=16)
        
        # Plot 1: Security scores by test type
        ax1 = axes[0, 0]
        test_names = []
        test_scores = []
        
        for test_result in analysis_results['attack_resistance_tests']:
            test_names.append(test_result['test_name'])
            test_scores.append(test_result['security_score'])
        
        if test_names and test_scores:
            bars = ax1.bar(test_names, test_scores)
            ax1.set_title('Attack Resistance Test Scores')
            ax1.set_ylabel('Security Score')
            ax1.set_ylim(0, 100)
            
            # Add score labels on bars
            for bar, score in zip(bars, test_scores):
                height = bar.get_height()
                ax1.text(bar.get_x() + bar.get_width()/2., height + 1,
                        f'{score:.1f}', ha='center', va='bottom')
        
        # Plot 2: Complexity ratings distribution
        ax2 = axes[0, 1]
        complexity_counts = analysis_results['overall_security_assessment']['complexity_distribution']
        ratings = list(complexity_counts.keys())
        counts = list(complexity_counts.values())
        
        wedges, texts, autotexts = ax2.pie(counts, labels=ratings, autopct='%1.1f%%')
        ax2.set_title('Polynomial Complexity Distribution')
        
        # Plot 3: Security score trends by polynomial degree
        ax3 = axes[1, 0]
        degrees = []
        complexity_scores = []
        
        for degree_key, poly_analysis in analysis_results['polynomial_analyses'].items():
            degree = int(degree_key.split('_')[1])
            complexity = poly_analysis['complexity_analysis']
            
            # Convert rating to numeric
            rating_scores = {'Low': 25, 'Medium': 50, 'Medium-High': 75, 'High': 100}
            score = rating_scores.get(complexity['complexity_rating'], 50)
            
            degrees.append(degree)
            complexity_scores.append(score)
        
        if degrees and complexity_scores:
            ax3.plot(degrees, complexity_scores, marker='o', linewidth=2, markersize=8)
            ax3.set_title('Security vs Polynomial Degree')
            ax3.set_xlabel('Polynomial Degree')
            ax3.set_ylabel('Security Score')
            ax3.grid(True, alpha=0.3)
            ax3.set_ylim(0, 100)
        
        # Plot 4: Overall security assessment
        ax4 = axes[1, 1]
        assessment = analysis_results['overall_security_assessment']
        
        # Create summary metrics visualization
        metrics = ['Average Score', 'Minimum Score']
        values = [assessment['average_security_score'], assessment['minimum_security_score']]
        
        bars = ax4.bar(metrics, values)
        ax4.set_title('Overall Security Assessment')
        ax4.set_ylabel('Security Score')
        ax4.set_ylim(0, 100)
        
        # Color bars based on score
        for bar, value in zip(bars, values):
            if value >= 80:
                bar.set_color('green')
            elif value >= 60:
                bar.set_color('orange')
            else:
                bar.set_color('red')
            
            # Add score label
            height = bar.get_height()
            ax4.text(bar.get_x() + bar.get_width()/2., height + 1,
                    f'{value:.1f}', ha='center', va='bottom')
        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'security_analysis.png'), dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Security analysis visualization saved to {output_dir}")


# Utility functions for quick security testing
def quick_security_check(polynomial_degree: int = 5) -> Dict[str, Any]:
    """
    Run a quick security check for demonstration purposes.
    
    Args:
        polynomial_degree: Polynomial degree to test
        
    Returns:
        Quick security analysis results
    """
    validator = ComprehensiveSecurityValidator()
    return validator.run_full_security_analysis(
        polynomial_degrees=[polynomial_degree],
        test_iterations=50
    )