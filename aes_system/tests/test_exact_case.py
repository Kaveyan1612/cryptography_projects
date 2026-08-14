#!/usr/bin/env python3
"""
Test the exact case from the user's error
"""

import sys
import os

# Add python directory to path
python_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'python')
sys.path.insert(0, python_dir)

from aes_core_simple import SimpleAES, SimpleFileCrypto, SimpleAESMode

def test_exact_error_case():
    """Test the exact case from the user's error"""
    print("Testing exact error case...")
    
    # The exact input from the user
    user_input = """Ciphertext (hex):
d17afc882b5b

IV (hex):
0a2b24c324edf7024d1f36713ac79b0a"""
    
    print(f"User input:\n{user_input}")
    
    # Simulate GUI parsing
    ciphertext_hex = None
    iv_hex = None
    
    if "Ciphertext (hex):" in user_input and "IV (hex):" in user_input:
        parts = user_input.split("IV (hex):")
        ciphertext_part = parts[0].strip()
        iv_part = parts[1].strip()
        
        if "Ciphertext (hex):" in ciphertext_part:
            ciphertext_hex = ciphertext_part.split("Ciphertext (hex):")[1].strip()
        else:
            ciphertext_hex = ciphertext_part.strip()
        
        iv_hex = iv_part.strip()
    
    print(f"\nExtracted ciphertext_hex: '{ciphertext_hex}' (length: {len(ciphertext_hex)})")
    print(f"Extracted iv_hex: '{iv_hex}' (length: {len(iv_hex)})")
    
    # Test conversion
    try:
        ciphertext = SimpleFileCrypto.hex_to_key(ciphertext_hex)
        print(f"✓ Ciphertext converted: {ciphertext.hex()}")
    except Exception as e:
        print(f"✗ Ciphertext conversion failed: {e}")
        return False
    
    try:
        iv = SimpleFileCrypto.hex_to_key(iv_hex)
        print(f"✓ IV converted: {iv.hex()}")
    except Exception as e:
        print(f"✗ IV conversion failed: {e}")
        return False
    
    # Test with actual encryption to see if this is valid
    key = SimpleFileCrypto.generate_key(256)
    mode = SimpleAESMode.CBC
    
    try:
        aes = SimpleAES(key, mode)
        plaintext = aes.decrypt(ciphertext, iv)
        decrypted_text = plaintext.decode('utf-8', errors='ignore')
        print(f"✓ Decryption result: '{decrypted_text}'")
    except Exception as e:
        print(f"✗ Decryption failed: {e}")
        # This might fail if the ciphertext wasn't created with this key
        print("  (This is expected if ciphertext wasn't created with this key)")
    
    print("\n✅ Exact error case handling test completed!")
    return True

if __name__ == "__main__":
    success = test_exact_error_case()
    sys.exit(0 if success else 1)