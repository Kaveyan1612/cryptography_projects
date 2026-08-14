#!/usr/bin/env python3
"""
Test copy-paste decryption functionality
"""

import sys
import os

# Add python directory to path
python_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'python')
sys.path.insert(0, python_dir)

from aes_core_simple import SimpleAES, SimpleFileCrypto, SimpleAESMode

def test_copy_paste_decryption():
    """Test copy-paste decryption as it would work in GUI"""
    print("Testing copy-paste decryption functionality...")
    
    key = SimpleFileCrypto.generate_key(256)
    plaintext = "hi"
    
    # Test with CBC mode (requires IV)
    print("\nTesting CBC mode copy-paste...")
    mode = SimpleAESMode.CBC
    
    # Encrypt as GUI would do
    aes = SimpleAES(key, mode)
    ciphertext, iv = aes.encrypt(plaintext.encode('utf-8'), None)
    
    # Format as GUI would display
    gui_output = f"Ciphertext (hex):\n{ciphertext.hex()}\n\nIV (hex):\n{iv.hex()}"
    print(f"GUI output format:\n{gui_output}")
    
    # Now simulate copy-paste decryption
    # Extract ciphertext and IV from GUI format
    ciphertext_hex = ciphertext.hex()
    iv_hex = iv.hex()
    
    # Convert back to bytes
    try:
        decrypted_ciphertext = SimpleFileCrypto.hex_to_key(ciphertext_hex)
        decrypted_iv = SimpleFileCrypto.hex_to_key(iv_hex)
        
        # Decrypt
        decrypted = aes.decrypt(decrypted_ciphertext, decrypted_iv)
        decrypted_text = decrypted.decode('utf-8')
        
        if decrypted_text == plaintext:
            print(f"✓ CBC copy-paste decryption works: '{decrypted_text}'")
        else:
            print(f"✗ CBC copy-paste failed: expected '{plaintext}', got '{decrypted_text}'")
            return False
            
    except Exception as e:
        print(f"✗ CBC copy-paste failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test with ECB mode (no IV required)
    print("\nTesting ECB mode copy-paste...")
    mode = SimpleAESMode.ECB
    
    # Encrypt as GUI would do
    aes = SimpleAES(key, mode)
    ciphertext, iv = aes.encrypt(plaintext.encode('utf-8'), None)
    
    # Format as GUI would display
    gui_output = f"Ciphertext (hex):\n{ciphertext.hex()}\n\nIV: Not required for ECB mode"
    print(f"GUI output format:\n{gui_output}")
    
    # Now simulate copy-paste decryption (no IV needed)
    ciphertext_hex = ciphertext.hex()
    
    try:
        decrypted_ciphertext = SimpleFileCrypto.hex_to_key(ciphertext_hex)
        
        # Decrypt without IV
        decrypted = aes.decrypt(decrypted_ciphertext, None)
        decrypted_text = decrypted.decode('utf-8')
        
        if decrypted_text == plaintext:
            print(f"✓ ECB copy-paste decryption works: '{decrypted_text}'")
        else:
            print(f"✗ ECB copy-paste failed: expected '{plaintext}', got '{decrypted_text}'")
            return False
            
    except Exception as e:
        print(f"✗ ECB copy-paste failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test with different modes
    modes_to_test = [SimpleAESMode.CFB, SimpleAESMode.OFB, SimpleAESMode.CTR]
    
    for mode in modes_to_test:
        print(f"\nTesting {mode.name} mode copy-paste...")
        
        try:
            aes = SimpleAES(key, mode)
            ciphertext, iv = aes.encrypt(plaintext.encode('utf-8'), None)
            
            # Format as GUI would display
            gui_output = f"Ciphertext (hex):\n{ciphertext.hex()}\n\nIV (hex):\n{iv.hex()}"
            
            # Extract and decrypt
            ciphertext_hex = ciphertext.hex()
            iv_hex = iv.hex()
            
            decrypted_ciphertext = SimpleFileCrypto.hex_to_key(ciphertext_hex)
            decrypted_iv = SimpleFileCrypto.hex_to_key(iv_hex)
            
            decrypted = aes.decrypt(decrypted_ciphertext, decrypted_iv)
            decrypted_text = decrypted.decode('utf-8')
            
            if decrypted_text == plaintext:
                print(f"✓ {mode.name} copy-paste decryption works: '{decrypted_text}'")
            else:
                print(f"✗ {mode.name} copy-paste failed: expected '{plaintext}', got '{decrypted_text}'")
                return False
                
        except Exception as e:
            print(f"✗ {mode.name} copy-paste failed with error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    print("\n✅ All copy-paste decryption tests passed!")
    return True

if __name__ == "__main__":
    success = test_copy_paste_decryption()
    sys.exit(0 if success else 1)