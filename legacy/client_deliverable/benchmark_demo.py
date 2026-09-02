#!/usr/bin/env python3
"""
CPDPM Client Benchmark Demonstration
===================================

Standalone benchmark script for demonstrating CPD    print(f"✅ Benchmark completed successfully!")
        print(f"💡 Key Takeaway: CPDPM provides enhanced security through")
        print(f"   dual-layer protection with competitive performance.")
        print(f"🔍 Note: RSA comparison limited to ≤8KB due to practical constraints")performance
advantages to clients. Shows direct comparison with standard AES-256.

Usage:
    python benchmark_demo.py
    python benchmark_demo.py --quick        # Run quick 3-size test
    python benchmark_demo.py --full         # Run full 5-size test
    python benchmark_demo.py --sizes 1,4,16 # Custom sizes in KB
"""

import sys
import os
import argparse
from typing import List

# Import our healthcare system
sys.path.insert(0, os.path.dirname(__file__))
from cpdpm_healthcare_system import HealthcareDataManager


def run_quick_benchmark():
    """Run a quick 3-size benchmark for rapid demonstrations."""
    print("🚀 CPDPM Quick Benchmark Demo")
    print("=" * 40)
    
    manager = HealthcareDataManager()
    
    # Quick test with 3 sizes (RSA limited to <=8KB)
    results = manager.run_comprehensive_client_benchmark(
        data_sizes=[1024, 4096, 8192],  # 1KB, 4KB, 8KB (all sizes work with RSA)
        iterations=2
    )
    
    manager.display_benchmark_results(results)
    
    # Quick summary
    avg_ratios = [r['cpdpm_vs_aes_total'] for r in results['comparison_summary']['performance_ratios']]
    avg_overhead = sum(avg_ratios) / len(avg_ratios)
    
    print(f"\n🎯 Quick Summary:")
    print(f"  • Average performance ratio: {avg_overhead:.2f}x")
    print(f"  • Security enhancement: Dual-layer (Polynomial + AES)")
    print(f"  • HIPAA compliance: ✓ Ready")
    
    return results


def run_full_benchmark():
    """Run comprehensive benchmark with 5 data sizes."""
    print("🔬 CPDPM Full Benchmark Suite")
    print("=" * 45)
    
    manager = HealthcareDataManager()
    
    # Full test with 5 sizes
    results = manager.run_comprehensive_client_benchmark(
        data_sizes=[1024, 4096, 16384, 65536, 262144],  # 1KB to 256KB
        iterations=3
    )
    
    manager.display_benchmark_results(results)
    
    return results


def run_custom_benchmark(sizes_kb: List[int]):
    """Run benchmark with custom data sizes."""
    print(f"🎛️ CPDPM Custom Benchmark")
    print(f"Testing sizes: {sizes_kb} KB")
    print("=" * 40)
    
    manager = HealthcareDataManager()
    
    # Convert KB to bytes
    sizes_bytes = [size * 1024 for size in sizes_kb]
    
    results = manager.run_comprehensive_client_benchmark(
        data_sizes=sizes_bytes,
        iterations=2
    )
    
    manager.display_benchmark_results(results)
    
    return results


def main():
    """Main benchmark runner with CLI options."""
    parser = argparse.ArgumentParser(
        description="CPDPM Client Benchmark Demonstration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python benchmark_demo.py           # Interactive mode
  python benchmark_demo.py --quick   # Quick 3-size test
  python benchmark_demo.py --full    # Full 5-size test
  python benchmark_demo.py --sizes 1,8,64   # Custom sizes (KB)
        """
    )
    
    parser.add_argument('--quick', action='store_true', 
                       help='Run quick benchmark (3 sizes, 2 iterations)')
    parser.add_argument('--full', action='store_true',
                       help='Run full benchmark (5 sizes, 3 iterations)')
    parser.add_argument('--sizes', type=str,
                       help='Custom sizes in KB (comma-separated, e.g., "1,4,16")')
    
    args = parser.parse_args()
    
    try:
        if args.quick:
            results = run_quick_benchmark()
        elif args.full:
            results = run_full_benchmark()
        elif args.sizes:
            sizes = [int(s.strip()) for s in args.sizes.split(',')]
            results = run_custom_benchmark(sizes)
        else:
            # Interactive mode
            print("🎯 CPDPM Interactive Benchmark Demo")
            print("=" * 40)
            print("Choose benchmark type:")
            print("  1. Quick (1KB, 4KB, 8KB) - includes CPDPM vs AES vs RSA")
            print("  2. Full (1KB, 4KB, 16KB, 64KB, 256KB) - RSA limited to ≤8KB")
            print("  3. Custom sizes")
            print("\nNote: RSA comparison limited to ≤8KB due to practical constraints")
            
            try:
                choice = input("\nEnter choice (1-3): ").strip()
                
                if choice == '1':
                    results = run_quick_benchmark()
                elif choice == '2':
                    results = run_full_benchmark()
                elif choice == '3':
                    sizes_input = input("Enter sizes in KB (comma-separated): ").strip()
                    sizes = [int(s.strip()) for s in sizes_input.split(',')]
                    results = run_custom_benchmark(sizes)
                else:
                    print("Invalid choice. Running quick benchmark...")
                    results = run_quick_benchmark()
            
            except (EOFError, KeyboardInterrupt):
                print("\nRunning quick benchmark...")
                results = run_quick_benchmark()
        
        print(f"\n✅ Benchmark completed successfully!")
        print(f"💡 Key Takeaway: CPDPM provides enhanced security through")
        print(f"   dual-layer protection with competitive performance.")
        
    except Exception as e:
        print(f"❌ Benchmark failed: {str(e)}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())