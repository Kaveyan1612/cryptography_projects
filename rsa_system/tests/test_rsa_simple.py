#!/usr/bin/env python3
"""
Simple test for RSA implementation
"""

import sys
import os

# Add python directory to path
python_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'python')
sys.path.insert(0, python_dir)

from rsa_core import RSA


def test_key_generation():
    """Test RSA key generation"""
    print("Testing RSA key generation...")
    
    rsa = RSA(1024)  # Use smaller key for faster testing
    public_key, private_key = rsa.generate_keypair()
    
    n, e = public_key
    print(f"Generated {n.bit_length()}-bit modulus")
    print(f"Public exponent: {e}")
    
    assert n > 0, "Key generation failed"
    print("✓ Key generation test passed")


def test_encryption_decryption():
    """Test RSA encryption and decryption"""
    print("\nTesting RSA encryption/decryption...")
    
    rsa = RSA(1024)
    public_key, private_key = rsa.generate_keypair()
    
    # Test with small integer
    plaintext = 12345
    ciphertext = rsa.encrypt(plaintext, public_key)
    decrypted = rsa.decrypt(ciphertext, private_key)
    
    assert decrypted == plaintext, "Encryption/decryption failed"
    print("✓ Encryption/decryption test passed")


def test_prime_testing():
    """Test prime number testing"""
    print("\nTesting prime number testing...")
    
    rsa = RSA(1024)
    
    # Test known primes
    assert rsa._is_prime(2), "Failed to detect prime 2"
    assert rsa._is_prime(3), "Failed to detect prime 3"
    assert rsa._is_prime(5), "Failed to detect prime 5"
    
    # Test known composites
    assert not rsa._is_prime(4), "Incorrectly detected 4 as prime"
    assert not rsa._is_prime(6), "Incorrectly detected 6 as prime"
    
    print("✓ Prime testing test passed")


def run_tests():
    """Run simple tests"""
    print("=" * 40)
    print("RSA Simple Test Suite")
    print("=" * 40)
    
    try:
        test_key_generation()
        test_encryption_decryption()
        test_prime_testing()
        
        print("\n" + "=" * 40)
        print("All RSA tests passed! ✓")
        print("=" * 40)
        return True
    except Exception as e:
        print(f"\n✗ Test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)