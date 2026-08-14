#!/usr/bin/env python3
"""
Test suite for RSA implementation
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from python.rsa_core import RSA, RSAKeySize


def test_key_generation():
    """Test RSA key generation"""
    print("Testing RSA key generation...")
    
    for key_size in [1024, 2048]:
        rsa = RSA(key_size)
        public_key, private_key = rsa.generate_keypair()
        
        # Verify key structure
        n, e = public_key
        n_priv, d, p, q, dP, dQ, qInv = private_key
        
        assert n == n_priv, "Modulus mismatch"
        assert e == 65537, "Public exponent not standard"
        assert p * q == n, "Prime multiplication incorrect"
        assert (p - 1) * (q - 1) > 0, "Invalid primes"
        
        print(f"✓ {key_size}-bit key generation passed")


def test_encryption_decryption():
    """Test RSA encryption and decryption"""
    print("\nTesting RSA encryption/decryption...")
    
    rsa = RSA(2048)
    public_key, private_key = rsa.generate_keypair()
    
    # Test with small integer
    plaintext = 123456789
    ciphertext = rsa.encrypt(plaintext, public_key)
    decrypted = rsa.decrypt(ciphertext, private_key)
    
    assert decrypted == plaintext, "RSA encryption/decryption failed"
    print("✓ Small integer encryption/decryption passed")
    
    # Test with bytes
    message = b"Secret message"
    encrypted = rsa.encrypt_bytes(message, public_key)
    decrypted = rsa.decrypt_bytes(encrypted, private_key)
    
    assert decrypted == message, "Bytes encryption/decryption failed"
    print("✓ Bytes encryption/decryption passed")


def test_digital_signatures():
    """Test RSA digital signatures"""
    print("\nTesting RSA digital signatures...")
    
    rsa = RSA(2048)
    public_key, private_key = rsa.generate_keypair()
    
    message = "Important document to sign"
    signature, hash_algo = rsa.sign(message, private_key)
    
    # Verify signature
    is_valid = rsa.verify(message, signature, public_key, hash_algo)
    assert is_valid, "Signature verification failed"
    print("✓ Digital signature creation passed")
    
    # Test with wrong message
    wrong_message = "Different message"
    is_valid_wrong = rsa.verify(wrong_message, signature, public_key, hash_algo)
    assert not is_valid_wrong, "Wrong message should not verify"
    print("✓ Digital signature verification passed")


def test_prime_generation():
    """Test prime number generation"""
    print("\nTesting prime number generation...")
    
    rsa = RSA(2048)
    
    # Test prime detection
    known_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for prime in known_primes:
        assert rsa._is_prime(prime), f"Failed to detect prime {prime}"
    
    known_composites = [4, 6, 8, 9, 10, 12, 14, 15, 16, 18]
    for composite in known_composites:
        assert not rsa._is_prime(composite), f"Incorrectly detected {composite} as prime"
    
    print("✓ Prime number generation passed")


def test_modular_inverse():
    """Test modular inverse calculation"""
    print("\nTesting modular inverse calculation...")
    
    rsa = RSA(2048)
    
    # Test cases where we know the answer
    assert rsa._mod_inverse(3, 7) == 5, "Modular inverse calculation failed"
    assert rsa._mod_inverse(7, 40) == 23, "Modular inverse calculation failed"
    
    print("✓ Modular inverse calculation passed")


def test_key_info():
    """Test key information extraction"""
    print("\nTesting key information extraction...")
    
    rsa = RSA(2048)
    public_key, private_key = rsa.generate_keypair()
    
    info = rsa.get_key_info()
    
    assert info['key_size'] == 2048, "Key size incorrect"
    assert info['modulus_bits'] == 2048, "Modulus bits incorrect"
    assert info['public_exponent'] == 65537, "Public exponent incorrect"
    
    print("✓ Key information extraction passed")


def test_key_export():
    """Test key export functionality"""
    print("\nTesting key export...")
    
    rsa = RSA(2048)
    public_key, private_key = rsa.generate_keypair()
    
    public_pem = rsa.export_public_key(public_key)
    private_pem = rsa.export_private_key()
    
    assert "BEGIN RSA PUBLIC KEY" in public_pem, "Public key export failed"
    assert "BEGIN RSA PRIVATE KEY" in private_pem, "Private key export failed"
    
    print("✓ Key export passed")


def test_large_messages():
    """Test encryption of large messages"""
    print("\nTesting large message encryption...")
    
    rsa = RSA(2048)
    public_key, private_key = rsa.generate_keypair()
    
    # Large message (multiple blocks)
    large_message = b'A' * 1000  # 1 KB
    
    encrypted = rsa.encrypt_bytes(large_message, public_key)
    decrypted = rsa.decrypt_bytes(encrypted, private_key)
    
    assert decrypted == large_message, "Large message encryption/decryption failed"
    print("✓ Large message encryption/decryption passed")


def test_crt_optimization():
    """Test CRT optimization for decryption"""
    print("\nTesting CRT optimization...")
    
    rsa = RSA(2048)
    public_key, private_key = rsa.generate_keypair()
    
    # Verify CRT parameters
    n, d, p, q, dP, dQ, qInv = private_key
    
    # Verify dP = d mod (p-1)
    assert dP == d % (p - 1), "dP calculation incorrect"
    
    # Verify dQ = d mod (q-1)
    assert dQ == d % (q - 1), "dQ calculation incorrect"
    
    # Verify qInv * q ≡ 1 (mod p)
    assert (qInv * q) % p == 1, "qInv calculation incorrect"
    
    print("✓ CRT optimization passed")


def run_all_tests():
    """Run all RSA tests"""
    print("=" * 50)
    print("RSA Test Suite")
    print("=" * 50)
    
    try:
        test_key_generation()
        test_encryption_decryption()
        test_digital_signatures()
        test_prime_generation()
        test_modular_inverse()
        test_key_info()
        test_key_export()
        test_large_messages()
        test_crt_optimization()
        
        print("\n" + "=" * 50)
        print("All RSA tests passed! ✓")
        print("=" * 50)
        return True
        
    except AssertionError as e:
        print(f"\n✗ Test failed: {str(e)}")
        return False
    except Exception as e:
        print(f"\n✗ Test error: {str(e)}")
        return False


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)