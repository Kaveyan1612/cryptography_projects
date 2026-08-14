#!/usr/bin/env python3
"""
Final test to verify AES GUI will work properly
"""

import sys
import os

# Add python directory to path
python_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'python')
sys.path.insert(0, python_dir)

print("Testing final AES GUI setup...")

try:
    from aes_core import AES, AESMode
    print("✓ AES and AESMode imported from aes_core")
    print(f"Available modes: {[mode.name for mode in AESMode]}")
except Exception as e:
    print(f"✗ Failed to import from aes_core: {e}")
    sys.exit(1)

try:
    from file_crypto import FileCrypto
    print("✓ FileCrypto imported")
except Exception as e:
    print(f"✗ Failed to import FileCrypto: {e}")
    sys.exit(1)

try:
    from aes_core_simple import SimpleAES, SimpleFileCrypto, SimpleAESMode
    print("✓ SimpleAES, SimpleFileCrypto, and SimpleAESMode imported")
    print(f"Available simple modes: {[mode.name for mode in SimpleAESMode]}")
except Exception as e:
    print(f"✗ Failed to import simple versions: {e}")
    sys.exit(1)

# Test functionality
print("\nTesting functionality...")
try:
    key = FileCrypto.generate_key(256)
    print(f"✓ Key generated: {key.hex()[:16]}...")
    
    text = "Test message for GUI"
    ciphertext, iv = FileCrypto.encrypt_text(text, key, AESMode.CBC)
    print(f"✓ Text encrypted with CBC mode: {ciphertext.hex()[:16]}...")
    
    decrypted = FileCrypto.decrypt_text(ciphertext, key, AESMode.CBC, iv)
    print(f"✓ Text decrypted: {decrypted}")
    
    if decrypted == text:
        print("✓ CBC mode works correctly!")
    else:
        print("✗ CBC mode decryption mismatch")
        sys.exit(1)
    
    # Test CFB mode
    ciphertext, iv = FileCrypto.encrypt_text(text, key, AESMode.CFB)
    print(f"✓ Text encrypted with CFB mode: {ciphertext.hex()[:16]}...")
    
    decrypted = FileCrypto.decrypt_text(ciphertext, key, AESMode.CFB, iv)
    print(f"✓ Text decrypted with CFB: {decrypted}")
    
    if decrypted == text:
        print("✓ CFB mode works correctly!")
    else:
        print("✗ CFB mode decryption mismatch")
        sys.exit(1)
    
    print("\n✅ All AES modes work correctly! GUI should function properly.")
    
except Exception as e:
    print(f"✗ Functionality test failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)