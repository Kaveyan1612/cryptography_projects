#!/usr/bin/env python3
"""
Test all AES decryption modes
"""

import sys
import os

# Add python directory to path
python_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'python')
sys.path.insert(0, python_dir)

from aes_core_simple import SimpleAES, SimpleFileCrypto, SimpleAESMode

def test_all_modes():
    """Test all AES modes with encryption and decryption"""
    print("Testing all AES decryption modes...")
    
    key = SimpleFileCrypto.generate_key(256)
    plaintext = b"This is a test message for AES decryption modes testing!"
    
    modes = [
        (SimpleAESMode.ECB, "ECB"),
        (SimpleAESMode.CBC, "CBC"),
        (SimpleAESMode.CFB, "CFB"),
        (SimpleAESMode.OFB, "OFB"),
        (SimpleAESMode.CTR, "CTR")
    ]
    
    for mode, mode_name in modes:
        print(f"\nTesting {mode_name} mode...")
        
        try:
            # Generate IV if needed
            if mode != SimpleAESMode.ECB:
                iv = SimpleFileCrypto.generate_iv()
            else:
                iv = None
            
            # Encrypt
            aes = SimpleAES(key, mode)
            ciphertext, used_iv = aes.encrypt(plaintext, iv)
            print(f"  ✓ Encryption successful: {ciphertext.hex()[:32]}...")
            
            # Decrypt
            decrypted = aes.decrypt(ciphertext, used_iv)
            print(f"  ✓ Decryption successful: {decrypted[:50]}...")
            
            # Verify
            if decrypted == plaintext:
                print(f"  ✓ {mode_name} mode works correctly!")
            else:
                print(f"  ✗ {mode_name} mode decryption mismatch!")
                print(f"    Expected: {plaintext}")
                print(f"    Got: {decrypted}")
                return False
                
        except Exception as e:
            print(f"  ✗ {mode_name} mode failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    print("\n✅ All AES decryption modes work correctly!")
    return True

def test_mode_specific_characteristics():
    """Test mode-specific characteristics"""
    print("\nTesting mode-specific characteristics...")
    
    key = SimpleFileCrypto.generate_key(256)
    
    # Test ECB - same plaintext should produce same ciphertext
    print("\nTesting ECB characteristic...")
    aes_ecb = SimpleAES(key, SimpleAESMode.ECB)
    plaintext = b"Test message"
    
    ciphertext1, _ = aes_ecb.encrypt(plaintext, None)
    ciphertext2, _ = aes_ecb.encrypt(plaintext, None)
    
    if ciphertext1 == ciphertext2:
        print("  ✓ ECB produces same ciphertext for same plaintext")
    else:
        print("  ✗ ECB should produce same ciphertext for same plaintext")
        return False
    
    # Test CBC - same plaintext with different IV should produce different ciphertext
    print("\nTesting CBC characteristic...")
    iv1 = SimpleFileCrypto.generate_iv()
    iv2 = SimpleFileCrypto.generate_iv()
    
    aes_cbc = SimpleAES(key, SimpleAESMode.CBC)
    ciphertext1, _ = aes_cbc.encrypt(plaintext, iv1)
    ciphertext2, _ = aes_cbc.encrypt(plaintext, iv2)
    
    if ciphertext1 != ciphertext2:
        print("  ✓ CBC produces different ciphertext with different IV")
    else:
        print("  ✗ CBC should produce different ciphertext with different IV")
        return False
    
    # Test CTR - random access (decrypt specific block)
    print("\nTesting CTR characteristic...")
    long_plaintext = b"This is a longer message to test CTR random access capability!"
    nonce = SimpleFileCrypto.generate_iv()
    
    aes_ctr = SimpleAES(key, SimpleAESMode.CTR)
    ciphertext, nonce = aes_ctr.encrypt(long_plaintext, nonce)
    
    # Decrypt the entire ciphertext
    decrypted = aes_ctr.decrypt(ciphertext, nonce)
    
    if decrypted == long_plaintext:
        print("  ✓ CTR mode works correctly")
    else:
        print("  ✗ CTR mode decryption failed")
        return False
    
    print("\n✅ Mode-specific characteristics verified!")
    return True

if __name__ == "__main__":
    success = test_all_modes()
    if success:
        success = test_mode_specific_characteristics()
    
    if success:
        print("\n🎉 All decryption mode tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed!")
        sys.exit(1)