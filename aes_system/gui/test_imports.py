#!/usr/bin/env python3
"""
Test proper AES imports for GUI
"""

import sys
import os

# Add python directory to path
python_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'python')
sys.path.insert(0, python_dir)

print("Testing imports...")

try:
    from aes_core import AES, AESMode
    print("✓ AES and AESMode imported from aes_core")
    print(f"Available modes: {[mode.name for mode in AESMode]}")
except Exception as e:
    print(f"✗ Failed to import from aes_core: {e}")

try:
    from file_crypto import FileCrypto
    print("✓ FileCrypto imported")
except Exception as e:
    print(f"✗ Failed to import FileCrypto: {e}")

try:
    from aes_core_simple import SimpleAES, SimpleFileCrypto, AESMode as SimpleAESMode
    print("✓ SimpleAES and SimpleAESMode imported")
    print(f"Available simple modes: {[mode.name for mode in SimpleAESMode]}")
except Exception as e:
    print(f"✗ Failed to import simple versions: {e}")

print("\nAll imports completed successfully!")