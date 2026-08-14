#!/usr/bin/env python3
"""
Test suite for AES implementation
"""

import sys
import os

# Add python directory to path
python_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'python')
sys.path.insert(0, python_dir)

from aes_core import AES, AESMode
from file_crypto import FileCrypto


def test_aes_encryption_decryption():
    """Test basic AES encryption and decryption"""
    print("Testing AES encryption/decryption...")
    
    # Test with AES-128
    key = b'0123456789abcdef'  # 128-bit key
    aes = AES(key, AESMode.CBC)
    plaintext = b'Hello, World! This is a test message.'
    iv = b'0123456789abcdef'
    
    ciphertext = aes.encrypt(plaintext, iv)
    decrypted = aes.decrypt(ciphertext, iv)
    
    assert decrypted == plaintext, "AES-128 encryption/decryption failed"
    print("✓ AES-128 encryption/decryption passed")
    
    # Test with AES-256
    key_256 = b'0123456789abcdef0123456789abcdef'  # 256-bit key
    aes_256 = AES(key_256, AESMode.CBC)
    ciphertext_256 = aes_256.encrypt(plaintext, iv)
    decrypted_256 = aes_256.decrypt(ciphertext_256, iv)
    
    assert decrypted_256 == plaintext, "AES-256 encryption/decryption failed"
    print("✓ AES-256 encryption/decryption passed")


def test_aes_modes():
    """Test different AES modes"""
    print("\nTesting AES modes...")
    
    key = b'0123456789abcdef'
    plaintext = b'Test message for different modes.'
    iv = b'0123456789abcdef'
    
    modes = [AESMode.ECB, AESMode.CBC, AESMode.CFB, AESMode.OFB, AESMode.CTR]
    
    for mode in modes:
        aes = AES(key, mode)
        mode_iv = None if mode == AESMode.ECB else iv
        ciphertext = aes.encrypt(plaintext, mode_iv)
        decrypted = aes.decrypt(ciphertext, mode_iv)
        
        assert decrypted == plaintext, f"AES {mode.name} mode failed"
        print(f"✓ AES {mode.name} mode passed")


def test_file_encryption():
    """Test file encryption and decryption"""
    print("\nTesting file encryption/decryption...")
    
    # Create test file
    test_file = '/tmp/test_aes_file.txt'
    encrypted_file = '/tmp/test_aes_file.enc'
    decrypted_file = '/tmp/test_aes_file_decrypted.txt'
    
    with open(test_file, 'w') as f:
        f.write("This is a test file for AES encryption.")
    
    # Generate key and encrypt
    key = FileCrypto.generate_key(256)
    
    _, iv = FileCrypto.encrypt_file(test_file, encrypted_file, key, AESMode.CBC)
    print("✓ File encryption passed")
    
    # Decrypt file
    FileCrypto.decrypt_file(encrypted_file, decrypted_file, key, AESMode.CBC, iv)
    print("✓ File decryption passed")
    
    # Verify content
    with open(test_file, 'r') as f:
        original = f.read()
    with open(decrypted_file, 'r') as f:
        decrypted = f.read()
    
    assert original == decrypted, "File content mismatch"
    print("✓ File content verification passed")
    
    # Clean up
    os.remove(test_file)
    os.remove(encrypted_file)
    os.remove(decrypted_file)


def test_text_encryption():
    """Test text encryption and decryption"""
    print("\nTesting text encryption/decryption...")
    
    key = FileCrypto.generate_key(256)
    text = "This is a secret message!"
    
    ciphertext, iv = FileCrypto.encrypt_text(text, key, AESMode.CBC)
    decrypted = FileCrypto.decrypt_text(ciphertext, key, AESMode.CBC, iv)
    
    assert decrypted == text, "Text encryption/decryption failed"
    print("✓ Text encryption/decryption passed")


def test_key_generation():
    """Test key generation"""
    print("\nTesting key generation...")
    
    for key_size in [128, 192, 256]:
        key = FileCrypto.generate_key(key_size)
        assert len(key) == key_size // 8, f"Key size {key_size} failed"
        print(f"✓ {key_size}-bit key generation passed")


def test_large_data():
    """Test encryption of large data"""
    print("\nTesting large data encryption...")
    
    key = FileCrypto.generate_key(256)
    large_data = b'A' * 10000  # 10 KB of data
    iv = FileCrypto.generate_iv()
    
    aes = AES(key, AESMode.CBC)
    ciphertext = aes.encrypt(large_data, iv)
    decrypted = aes.decrypt(ciphertext, iv)
    
    assert decrypted == large_data, "Large data encryption/decryption failed"
    print("✓ Large data encryption/decryption passed")


def run_all_tests():
    """Run all AES tests"""
    print("=" * 50)
    print("AES Test Suite")
    print("=" * 50)
    
    try:
        test_aes_encryption_decryption()
        test_aes_modes()
        test_file_encryption()
        test_text_encryption()
        test_key_generation()
        test_large_data()
        
        print("\n" + "=" * 50)
        print("All AES tests passed! ✓")
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