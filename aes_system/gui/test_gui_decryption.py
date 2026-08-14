#!/usr/bin/env python3
"""
Test GUI decryption with various input formats
"""

import sys
import os

# Add python directory to path
python_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'python')
sys.path.insert(0, python_dir)

from aes_core_simple import SimpleAES, SimpleFileCrypto, SimpleAESMode

def test_gui_format_parsing():
    """Test parsing of various GUI input formats"""
    print("Testing GUI format parsing...")
    
    key = SimpleFileCrypto.generate_key(256)
    plaintext = "hi"
    mode = SimpleAESMode.CBC
    
    # Encrypt
    aes = SimpleAES(key, mode)
    ciphertext, iv = aes.encrypt(plaintext.encode('utf-8'), None)
    
    # Create various input formats as they would appear in GUI
    test_cases = [
        # Full GUI format
        f"Ciphertext (hex):\n{ciphertext.hex()}\n\nIV (hex):\n{iv.hex()}",
        
        # Ciphertext only
        f"Ciphertext (hex):\n{ciphertext.hex()}",
        
        # Raw hex
        ciphertext.hex(),
        
        # With extra whitespace
        f"  Ciphertext (hex):\n  {ciphertext.hex()}  \n\n  IV (hex):\n  {iv.hex()}  ",
    ]
    
    for i, test_input in enumerate(test_cases, 1):
        print(f"\nTest case {i}: {repr(test_input[:50])}...")
        
        try:
            # Simulate GUI parsing logic
            ciphertext_hex = None
            iv_hex = None
            
            if "Ciphertext (hex):" in test_input and "IV (hex):" in test_input:
                parts = test_input.split("IV (hex):")
                ciphertext_part = parts[0].strip()
                iv_part = parts[1].strip()
                
                if "Ciphertext (hex):" in ciphertext_part:
                    ciphertext_hex = ciphertext_part.split("Ciphertext (hex):")[1].strip()
                else:
                    ciphertext_hex = ciphertext_part.strip()
                
                iv_hex = iv_part.strip()
            
            elif "Ciphertext (hex):" in test_input:
                ciphertext_hex = test_input.split("Ciphertext (hex):")[1].strip()
                iv_hex = None
            else:
                ciphertext_hex = test_input.strip()
                iv_hex = None
            
            # Clean up
            if ciphertext_hex:
                ciphertext_hex = ciphertext_hex.strip()
                if "IV" in ciphertext_hex:
                    ciphertext_hex = ciphertext_hex.split("IV")[0].strip()
            
            if iv_hex:
                iv_hex = iv_hex.strip()
            
            # Convert and decrypt
            if ciphertext_hex:
                ciphertext_bytes = SimpleFileCrypto.hex_to_key(ciphertext_hex)
                iv_bytes = SimpleFileCrypto.hex_to_key(iv_hex) if iv_hex else iv
                
                decrypted = aes.decrypt(ciphertext_bytes, iv_bytes)
                decrypted_text = decrypted.decode('utf-8')
                
                if decrypted_text == plaintext:
                    print(f"  ✓ Format {i} works correctly: '{decrypted_text}'")
                else:
                    print(f"  ✗ Format {i} failed: expected '{plaintext}', got '{decrypted_text}'")
                    return False
            else:
                print(f"  ✗ Format {i} failed: no ciphertext found")
                return False
                
        except Exception as e:
            print(f"  ✗ Format {i} failed with error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    print("\n✅ All GUI format parsing tests passed!")
    return True

if __name__ == "__main__":
    success = test_gui_format_parsing()
    sys.exit(0 if success else 1)