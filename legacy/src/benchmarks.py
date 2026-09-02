"""
Performance Benchmarking Suite for CPDPM

This module provides comprehensive benchmarking tools to compare CPDPM
performance against traditional encryption methods (AES, RSA) across
multiple metrics including execution time, memory usage, and security strength.

Author: CPDPM Research Team
"""

import time
import psutil
import os
import statistics
import base64
from typing import Dict, List, Tuple, Callable, Any
from dataclasses import dataclass, asdict
import json
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import numpy as np

from cpdpm_hybrid import CPDPMHybrid
from synthetic_data import SyntheticHealthcareGenerator, EncryptionDemoData


@dataclass
class BenchmarkResult:
    """Results from a single benchmark test."""
    algorithm: str
    operation: str
    data_size: int
    execution_time: float
    memory_usage_mb: float
    cpu_usage_percent: float
    key_size_bits: int
    success: bool
    error_message: str = ""
    additional_metrics: Dict[str, Any] = None


@dataclass
class BenchmarkSuite:
    """Complete benchmark suite results."""
    test_name: str
    timestamp: str
    results: List[BenchmarkResult]
    summary_statistics: Dict[str, Any]
    system_info: Dict[str, str]


class PerformanceBenchmark:
    """
    Performance benchmarking system for comparing CPDPM with traditional encryption.
    """
    
    def __init__(self):
        """Initialize benchmarking system."""
        self.cpdpm = CPDPMHybrid()
        self.backend = default_backend()
        self.results: List[BenchmarkResult] = []
        
    def _measure_performance(self, func: Callable, *args, **kwargs) -> Tuple[Any, float, float, float]:
        """
        Measure execution time, memory usage, and CPU usage of a function.
        
        Args:
            func: Function to benchmark
            *args, **kwargs: Arguments for the function
            
        Returns:
            Tuple of (result, execution_time, memory_mb, cpu_percent)
        """
        # Get initial system state
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Monitor CPU usage
        cpu_percent_start = psutil.cpu_percent()
        
        # Execute function with timing
        start_time = time.perf_counter()
        try:
            result = func(*args, **kwargs)
            success = True
            error_msg = ""
        except Exception as e:
            result = None
            success = False
            error_msg = str(e)
        end_time = time.perf_counter()
        
        # Calculate metrics
        execution_time = end_time - start_time
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_usage = final_memory - initial_memory
        cpu_percent_end = psutil.cpu_percent()
        avg_cpu = (cpu_percent_start + cpu_percent_end) / 2
        
        return result, execution_time, memory_usage, avg_cpu, success, error_msg
    
    def benchmark_cpdpm_encryption(self, 
                                  data: bytes, 
                                  password: str = "test_password_123",
                                  context: str = "benchmark_test") -> BenchmarkResult:
        """Benchmark CPDPM encryption performance."""
        
        def encrypt_func():
            return self.cpdpm.encrypt(data, password, context)
        
        result, exec_time, memory, cpu, success, error = self._measure_performance(encrypt_func)
        
        return BenchmarkResult(
            algorithm="CPDPM-AES256",
            operation="encrypt",
            data_size=len(data),
            execution_time=exec_time,
            memory_usage_mb=memory,
            cpu_usage_percent=cpu,
            key_size_bits=256 + 64,  # AES-256 + polynomial complexity estimate
            success=success,
            error_message=error,
            additional_metrics={
                'polynomial_degree': 5,
                'hybrid_layers': 2
            }
        )
    
    def benchmark_cpdpm_decryption(self, 
                                  encrypted_package: dict, 
                                  password: str = "test_password_123") -> BenchmarkResult:
        """Benchmark CPDPM decryption performance."""
        
        def decrypt_func():
            return self.cpdpm.decrypt(encrypted_package, password)
        
        result, exec_time, memory, cpu, success, error = self._measure_performance(decrypt_func)
        
        return BenchmarkResult(
            algorithm="CPDPM-AES256",
            operation="decrypt",
            data_size=len(encrypted_package.get('ciphertext', '')),
            execution_time=exec_time,
            memory_usage_mb=memory,
            cpu_usage_percent=cpu,
            key_size_bits=256 + 64,
            success=success,
            error_message=error
        )
    
    def benchmark_aes_encryption(self, data: bytes, password: str = "test_password_123") -> BenchmarkResult:
        """Benchmark standard AES-256 encryption performance."""
        
        def encrypt_func():
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives.padding import PKCS7
            
            salt = os.urandom(16)
            iv = os.urandom(16)
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=self.backend
            )
            key = kdf.derive(password.encode())
            
            padder = PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            return {'ciphertext': ciphertext, 'salt': salt, 'iv': iv}
        
        result, exec_time, memory, cpu, success, error = self._measure_performance(encrypt_func)
        
        return BenchmarkResult(
            algorithm="AES-256-CBC",
            operation="encrypt",
            data_size=len(data),
            execution_time=exec_time,
            memory_usage_mb=memory,
            cpu_usage_percent=cpu,
            key_size_bits=256,
            success=success,
            error_message=error
        )
    
    def benchmark_rsa_encryption(self, data: bytes) -> BenchmarkResult:
        """Benchmark RSA encryption performance."""
        
        def encrypt_func():
            # Generate RSA key pair
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=self.backend
            )
            public_key = private_key.public_key()
            
            # RSA can only encrypt limited data, so we'll encrypt in chunks
            max_chunk_size = 190  # For 2048-bit RSA with OAEP padding
            encrypted_chunks = []
            
            for i in range(0, len(data), max_chunk_size):
                chunk = data[i:i + max_chunk_size]
                encrypted_chunk = public_key.encrypt(
                    chunk,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                encrypted_chunks.append(encrypted_chunk)
            
            return {'encrypted_chunks': encrypted_chunks, 'private_key': private_key}
        
        result, exec_time, memory, cpu, success, error = self._measure_performance(encrypt_func)
        
        return BenchmarkResult(
            algorithm="RSA-2048",
            operation="encrypt",
            data_size=len(data),
            execution_time=exec_time,
            memory_usage_mb=memory,
            cpu_usage_percent=cpu,
            key_size_bits=2048,
            success=success,
            error_message=error
        )
    
    def run_comprehensive_benchmark(self, 
                                  data_sizes: List[int] = None,
                                  iterations: int = 5) -> BenchmarkSuite:
        """
        Run comprehensive benchmarks comparing all encryption methods.
        
        Args:
            data_sizes: List of data sizes to test (in bytes)
            iterations: Number of iterations per test for averaging
            
        Returns:
            Complete benchmark suite results
        """
        if data_sizes is None:
            data_sizes = [1024, 8192, 65536, 524288]  # 1KB, 8KB, 64KB, 512KB
        
        print("Starting comprehensive encryption benchmark...")
        
        # Generate test data
        generator = SyntheticHealthcareGenerator(seed=42)
        demo_data = EncryptionDemoData(generator)
        
        all_results = []
        
        for size in data_sizes:
            print(f"\nTesting data size: {size} bytes")
            
            # Generate test data of specified size
            if size <= 8192:
                # Use synthetic healthcare data for smaller sizes
                test_cases = demo_data.create_encryption_test_cases()
                test_data = test_cases[0][1][:size] if len(test_cases[0][1]) >= size else test_cases[0][1]
                # Pad if necessary
                if len(test_data) < size:
                    test_data += b'0' * (size - len(test_data))
                else:
                    test_data = test_data[:size]
            else:
                # Generate random data for larger sizes
                test_data = os.urandom(size)
            
            # Run multiple iterations for each algorithm
            for iteration in range(iterations):
                print(f"  Iteration {iteration + 1}/{iterations}")
                
                # CPDPM Encryption
                cpdpm_encrypt_result = self.benchmark_cpdpm_encryption(test_data)
                cpdpm_encrypt_result.additional_metrics = cpdpm_encrypt_result.additional_metrics or {}
                cpdpm_encrypt_result.additional_metrics['iteration'] = iteration
                all_results.append(cpdpm_encrypt_result)
                
                # CPDPM Decryption (if encryption succeeded)
                if cpdpm_encrypt_result.success:
                    encrypted_package = self.cpdpm.encrypt(test_data, "test_password_123", "benchmark_test")
                    cpdpm_decrypt_result = self.benchmark_cpdpm_decryption(encrypted_package)
                    cpdpm_decrypt_result.additional_metrics = {'iteration': iteration}
                    all_results.append(cpdpm_decrypt_result)
                
                # AES Encryption
                aes_result = self.benchmark_aes_encryption(test_data)
                aes_result.additional_metrics = {'iteration': iteration}
                all_results.append(aes_result)
                
                # RSA Encryption (only for smaller data due to RSA limitations)
                if size <= 8192:  # RSA practical limit for demo
                    rsa_result = self.benchmark_rsa_encryption(test_data)
                    rsa_result.additional_metrics = {'iteration': iteration}
                    all_results.append(rsa_result)
        
        # Generate summary statistics
        summary_stats = self._calculate_summary_statistics(all_results)
        
        # Get system information
        system_info = self._get_system_info()
        
        benchmark_suite = BenchmarkSuite(
            test_name="CPDPM Comprehensive Performance Benchmark",
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            results=all_results,
            summary_statistics=summary_stats,
            system_info=system_info
        )
        
        print("\nBenchmark completed!")
        return benchmark_suite
    
    def _calculate_summary_statistics(self, results: List[BenchmarkResult]) -> Dict[str, Any]:
        """Calculate summary statistics from benchmark results."""
        stats = {}
        
        # Group results by algorithm and operation
        grouped = {}
        for result in results:
            key = f"{result.algorithm}_{result.operation}"
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(result)
        
        for key, group in grouped.items():
            successful_results = [r for r in group if r.success]
            if not successful_results:
                continue
            
            exec_times = [r.execution_time for r in successful_results]
            memory_usage = [r.memory_usage_mb for r in successful_results]
            
            stats[key] = {
                'count': len(successful_results),
                'avg_execution_time': statistics.mean(exec_times),
                'median_execution_time': statistics.median(exec_times),
                'std_execution_time': statistics.stdev(exec_times) if len(exec_times) > 1 else 0,
                'avg_memory_usage': statistics.mean(memory_usage),
                'median_memory_usage': statistics.median(memory_usage),
                'success_rate': len(successful_results) / len(group) * 100
            }
        
        return stats
    
    def _get_system_info(self) -> Dict[str, str]:
        """Get system information for benchmark context."""
        return {
            'cpu_count': str(psutil.cpu_count()),
            'cpu_freq': f"{psutil.cpu_freq().current:.0f} MHz" if psutil.cpu_freq() else "Unknown",
            'total_memory': f"{psutil.virtual_memory().total / (1024**3):.1f} GB",
            'python_version': f"{os.sys.version_info.major}.{os.sys.version_info.minor}.{os.sys.version_info.micro}",
            'platform': os.sys.platform
        }
    
    def save_benchmark_results(self, suite: BenchmarkSuite, output_file: str):
        """Save benchmark results to JSON file."""
        # Convert dataclass to dict for JSON serialization
        suite_dict = asdict(suite)
        
        with open(output_file, 'w') as f:
            json.dump(suite_dict, f, indent=2, default=str)
        
        print(f"Benchmark results saved to {output_file}")
    
    def generate_performance_report(self, suite: BenchmarkSuite, output_dir: str):
        """Generate comprehensive performance report with visualizations."""
        os.makedirs(output_dir, exist_ok=True)
        
        # Convert results to DataFrame for analysis
        results_df = pd.DataFrame([asdict(r) for r in suite.results])
        
        # Set up plotting style
        plt.style.use('default')
        sns.set_palette("husl")
        
        # Create performance comparison plots
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('CPDPM vs Traditional Encryption Performance Comparison', fontsize=16)
        
        # Execution time comparison
        successful_results = results_df[results_df['success'] == True]
        
        # Plot 1: Execution time by algorithm
        ax1 = axes[0, 0]
        sns.boxplot(data=successful_results, x='algorithm', y='execution_time', ax=ax1)
        ax1.set_title('Execution Time Distribution')
        ax1.set_ylabel('Time (seconds)')
        ax1.tick_params(axis='x', rotation=45)
        
        # Plot 2: Memory usage by algorithm
        ax2 = axes[0, 1]
        sns.boxplot(data=successful_results, x='algorithm', y='memory_usage_mb', ax=ax2)
        ax2.set_title('Memory Usage Distribution')
        ax2.set_ylabel('Memory (MB)')
        ax2.tick_params(axis='x', rotation=45)
        
        # Plot 3: Performance vs data size
        ax3 = axes[1, 0]
        for algorithm in successful_results['algorithm'].unique():
            alg_data = successful_results[successful_results['algorithm'] == algorithm]
            grouped = alg_data.groupby('data_size')['execution_time'].mean()
            ax3.plot(grouped.index, grouped.values, marker='o', label=algorithm)
        ax3.set_title('Execution Time vs Data Size')
        ax3.set_xlabel('Data Size (bytes)')
        ax3.set_ylabel('Time (seconds)')
        ax3.set_xscale('log')
        ax3.legend()
        ax3.grid(True, alpha=0.3)
        
        # Plot 4: Security strength comparison
        ax4 = axes[1, 1]
        algorithms = successful_results['algorithm'].unique()
        key_sizes = [successful_results[successful_results['algorithm'] == alg]['key_size_bits'].iloc[0] 
                    for alg in algorithms]
        bars = ax4.bar(algorithms, key_sizes)
        ax4.set_title('Key Size Comparison')
        ax4.set_ylabel('Key Size (bits)')
        ax4.tick_params(axis='x', rotation=45)
        
        # Add value labels on bars
        for bar, size in zip(bars, key_sizes):
            height = bar.get_height()
            ax4.text(bar.get_x() + bar.get_width()/2., height + 10,
                    f'{size}', ha='center', va='bottom')
        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'performance_comparison.png'), dpi=300, bbox_inches='tight')
        plt.close()
        
        # Generate summary report
        self._generate_text_report(suite, os.path.join(output_dir, 'benchmark_report.txt'))
        
        print(f"Performance report generated in {output_dir}")
    
    def _generate_text_report(self, suite: BenchmarkSuite, output_file: str):
        """Generate detailed text report."""
        with open(output_file, 'w') as f:
            f.write("CPDPM Performance Benchmark Report\n")
            f.write("=" * 50 + "\n\n")
            
            f.write(f"Test Date: {suite.timestamp}\n")
            f.write(f"Test Name: {suite.test_name}\n\n")
            
            f.write("System Information:\n")
            f.write("-" * 20 + "\n")
            for key, value in suite.system_info.items():
                f.write(f"{key.replace('_', ' ').title()}: {value}\n")
            f.write("\n")
            
            f.write("Summary Statistics:\n")
            f.write("-" * 20 + "\n")
            for test_key, stats in suite.summary_statistics.items():
                f.write(f"\n{test_key.replace('_', ' - ').title()}:\n")
                f.write(f"  Average Execution Time: {stats['avg_execution_time']:.4f} seconds\n")
                f.write(f"  Median Execution Time: {stats['median_execution_time']:.4f} seconds\n")
                f.write(f"  Standard Deviation: {stats['std_execution_time']:.4f} seconds\n")
                f.write(f"  Average Memory Usage: {stats['avg_memory_usage']:.2f} MB\n")
                f.write(f"  Success Rate: {stats['success_rate']:.1f}%\n")
            
            f.write("\n" + "=" * 50 + "\n")
            f.write("Detailed Results:\n")
            f.write("-" * 20 + "\n")
            
            for result in suite.results:
                f.write(f"\nAlgorithm: {result.algorithm}\n")
                f.write(f"Operation: {result.operation}\n")
                f.write(f"Data Size: {result.data_size} bytes\n")
                f.write(f"Execution Time: {result.execution_time:.4f} seconds\n")
                f.write(f"Memory Usage: {result.memory_usage_mb:.2f} MB\n")
                f.write(f"Key Size: {result.key_size_bits} bits\n")
                f.write(f"Success: {result.success}\n")
                if not result.success:
                    f.write(f"Error: {result.error_message}\n")
                f.write("-" * 30 + "\n")


class SecurityBenchmark:
    """
    Security-focused benchmarks for analyzing cryptographic strength.
    """
    
    def __init__(self):
        """Initialize security benchmark."""
        self.cpdpm = CPDPMHybrid()
    
    def test_key_space_analysis(self, polynomial_degrees: List[int] = None) -> Dict[str, Any]:
        """
        Analyze effective key space for different polynomial configurations.
        
        Args:
            polynomial_degrees: List of polynomial degrees to test
            
        Returns:
            Key space analysis results
        """
        if polynomial_degrees is None:
            polynomial_degrees = [3, 5, 7, 9]
        
        results = {}
        
        for degree in polynomial_degrees:
            # Estimate key space size
            coefficient_space = 2**31 - 1  # Prime modulus
            num_coefficients = degree + 1
            
            # Rough estimate of polynomial key space
            poly_key_space = coefficient_space ** num_coefficients
            
            # Combined with AES-256
            combined_key_space = 2**256 * poly_key_space
            
            results[f"degree_{degree}"] = {
                'polynomial_degree': degree,
                'coefficient_count': num_coefficients,
                'polynomial_key_space_log2': np.log2(poly_key_space),
                'aes_key_space_log2': 256,
                'combined_key_space_log2': 256 + np.log2(poly_key_space),
                'estimated_security_bits': min(256, 256 + np.log2(poly_key_space) * 0.1)
            }
        
        return results
    
    def test_avalanche_effect(self, test_data: bytes = None, iterations: int = 100) -> Dict[str, float]:
        """
        Test avalanche effect - how much output changes with small input changes.
        
        Args:
            test_data: Test data (generated if None)
            iterations: Number of test iterations
            
        Returns:
            Avalanche effect statistics
        """
        if test_data is None:
            test_data = b"This is a test message for avalanche effect analysis."
        
        password = "test_password_123"
        context = "avalanche_test"
        
        # Original encryption
        original_encrypted = self.cpdpm.encrypt(test_data, password, context)
        original_ciphertext = original_encrypted['ciphertext']
        
        bit_changes = []
        
        for i in range(iterations):
            # Create modified input (flip one bit)
            modified_data = bytearray(test_data)
            byte_index = i % len(modified_data)
            bit_index = i % 8
            modified_data[byte_index] ^= (1 << bit_index)
            
            # Encrypt modified input
            modified_encrypted = self.cpdpm.encrypt(bytes(modified_data), password, context)
            modified_ciphertext = modified_encrypted['ciphertext']
            
            # Calculate bit differences
            original_bytes = base64.b64decode(original_ciphertext)
            modified_bytes = base64.b64decode(modified_ciphertext)
            
            if len(original_bytes) == len(modified_bytes):
                different_bits = 0
                total_bits = len(original_bytes) * 8
                
                for orig_byte, mod_byte in zip(original_bytes, modified_bytes):
                    xor_result = orig_byte ^ mod_byte
                    different_bits += bin(xor_result).count('1')
                
                change_percentage = (different_bits / total_bits) * 100
                bit_changes.append(change_percentage)
        
        if bit_changes:
            return {
                'average_bit_change_percentage': statistics.mean(bit_changes),
                'min_bit_change_percentage': min(bit_changes),
                'max_bit_change_percentage': max(bit_changes),
                'std_bit_change_percentage': statistics.stdev(bit_changes) if len(bit_changes) > 1 else 0,
                'ideal_avalanche_percentage': 50.0,  # Ideal avalanche effect
                'avalanche_quality': 'Good' if statistics.mean(bit_changes) > 40 else 'Fair' if statistics.mean(bit_changes) > 25 else 'Poor'
            }
        else:
            return {'error': 'No valid avalanche measurements obtained'}


# Utility function for easy benchmarking
def run_quick_benchmark(data_size: int = 8192) -> BenchmarkSuite:
    """
    Run a quick benchmark for demonstration purposes.
    
    Args:
        data_size: Size of test data in bytes
        
    Returns:
        Benchmark results
    """
    benchmark = PerformanceBenchmark()
    return benchmark.run_comprehensive_benchmark(
        data_sizes=[data_size],
        iterations=3
    )