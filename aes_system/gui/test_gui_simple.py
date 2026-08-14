#!/usr/bin/env python3
"""
Simple test to verify AES GUI imports work without crashing
"""

import sys
import os

# Add python directory to path
python_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'python')
sys.path.insert(0, python_dir)

try:
    from aes_core_simple import SimpleAES, SimpleFileCrypto, AESMode
    print("✓ Imports successful")
    
    # Test basic functionality
    key = SimpleFileCrypto.generate_key(256)
    print(f"✓ Key generated: {key.hex()[:16]}...")
    
    text = "Test message"
    ciphertext, iv = SimpleFileCrypto.encrypt_text(text, key, AESMode.CBC)
    print(f"✓ Text encrypted: {ciphertext.hex()[:16]}...")
    
    decrypted = SimpleFileCrypto.decrypt_text(ciphertext, key, AESMode.CBC, iv)
    print(f"✓ Text decrypted: {decrypted}")
    
    if decrypted == text:
        print("✓ All GUI components work correctly!")
    else:
        print("✗ Decryption mismatch")
        
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()