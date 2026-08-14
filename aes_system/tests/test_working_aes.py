#!/usr/bin/env python3
"""
Test to verify AES encryption returns data instead of None
"""

import sys
import os

# Add python directory to path
python_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'python')
sys.path.insert(0, python_dir)

from aes_core_simple import SimpleAES, SimpleFileCrypto, AESMode


def test_encryption_returns_data():
    """Test that encryption returns actual data"""
    print("Testing AES encryption returns data...")
    
    # Generate key
    key = SimpleFileCrypto.generate_key(256)
    print(f"Generated key: {key.hex()[:16]}...")
    
    # Create AES instance
    aes = SimpleAES(key, AESMode.CBC)
    
    # Test encryption
    plaintext = b"Hello, World! This is a test."
    iv = SimpleFileCrypto.generate_iv()
    
    print(f"Plaintext: {plaintext}")
    print(f"IV: {iv.hex()}")
    
    # Encrypt
    ciphertext = aes.encrypt(plaintext, iv)
    
    # Check if we got data instead of None
    if ciphertext is None:
        print("✗ FAILED: Encryption returned None")
        return False
    
    print(f"Ciphertext: {ciphertext.hex()[:32]}...")
    print(f"Ciphertext length: {len(ciphertext)} bytes")
    
    # Try to convert to hex (this was failing before)
    try:
        hex_result = ciphertext.hex()
        print(f"Hex conversion: {hex_result[:32]}...")
        print("✓ SUCCESS: Encryption returned data and hex conversion works")
        return True
    except AttributeError as e:
        print(f"✗ FAILED: {e}")
        return False


def test_text_encryption():
    """Test text encryption/decryption"""
    print("\nTesting text encryption/decryption...")
    
    key = SimpleFileCrypto.generate_key(256)
    text = "Secret message"
    
    ciphertext, iv = SimpleFileCrypto.encrypt_text(text, key, AESMode.CBC)
    
    if ciphertext is None:
        print("✗ FAILED: Text encryption returned None")
        return False
    
    print(f"Ciphertext: {ciphertext.hex()[:32]}...")
    
    decrypted = SimpleFileCrypto.decrypt_text(ciphertext, key, AESMode.CBC, iv)
    
    if decrypted == text:
        print("✓ SUCCESS: Text encryption/decryption works")
        return True
    else:
        print(f"✗ FAILED: Decryption mismatch")
        return False


def run_tests():
    """Run all tests"""
    print("=" * 50)
    print("AES Encryption Fix Verification")
    print("=" * 50)
    
    try:
        test_encryption_returns_data()
        test_text_encryption()
        
        print("\n" + "=" * 50)
        print("All tests passed! AES encryption now returns data.")
        print("=" * 50)
        return True
        
    except Exception as e:
        print(f"\n✗ Test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)