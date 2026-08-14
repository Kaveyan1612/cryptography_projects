#!/usr/bin/env python3
"""
Simple test for AES implementation
"""

import sys
import os

# Add python directory to path
python_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'python')
sys.path.insert(0, python_dir)

# Now import
from aes_core_simple import SimpleAES, SimpleFileCrypto, SimpleAESMode


def test_basic_encryption():
    """Test basic AES encryption"""
    print("Testing basic AES encryption...")
    
    key = b'0123456789abcdef0123456789abcdef'  # 128-bit key
    aes = SimpleAES(key, SimpleAESMode.ECB)  # Use SimpleAES
    plaintext = b'Hello, World!!!!'  # 16 bytes (exactly one block)
    
    # Test block encryption directly
    ciphertext_block = aes._encrypt_block(plaintext)
    decrypted_block = aes._decrypt_block(ciphertext_block)
    
    if decrypted_block == plaintext:
        print("✓ Basic encryption test passed")
    else:
        print(f"✗ Block encryption failed")
        print(f"Plaintext: {plaintext.hex()}")
        print(f"Ciphertext: {ciphertext_block.hex()}")
        print(f"Decrypted: {decrypted_block.hex()}")


def test_key_generation():
    """Test key generation"""
    print("\nTesting key generation...")
    
    for key_size in [128, 192, 256]:
        key = SimpleFileCrypto.generate_key(key_size)
        assert len(key) == key_size // 8, f"Key size {key_size} failed"
        print(f"✓ {key_size}-bit key generation passed")


def run_tests():
    """Run simple tests"""
    print("=" * 40)
    print("AES Simple Test Suite")
    print("=" * 40)
    
    try:
        test_basic_encryption()
        test_key_generation()
        
        print("\n" + "=" * 40)
        print("All tests passed! ✓")
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