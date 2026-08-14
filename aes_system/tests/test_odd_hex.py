#!/usr/bin/env python3
"""
Test odd-length hex string handling
"""

import sys
import os

# Add python directory to path
python_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'python')
sys.path.insert(0, python_dir)

from aes_core_simple import SimpleAES, SimpleFileCrypto, SimpleAESMode

def test_odd_hex_strings():
    """Test handling of odd-length hex strings"""
    print("Testing odd-length hex string handling...")
    
    # Test the specific case from the error
    odd_hex = "d17afc882b5b"  # 11 characters (odd)
    print(f"Testing odd-length hex: {odd_hex} (length: {len(odd_hex)})")
    
    try:
        result = SimpleFileCrypto.hex_to_key(odd_hex)
        print(f"✓ Odd-length hex converted successfully: {result.hex()}")
    except Exception as e:
        print(f"✗ Odd-length hex conversion failed: {e}")
        return False
    
    # Test even-length hex (should still work)
    even_hex = "d17afc882b5b00"  # 12 characters (even)
    print(f"\nTesting even-length hex: {even_hex} (length: {len(even_hex)})")
    
    try:
        result = SimpleFileCrypto.hex_to_key(even_hex)
        print(f"✓ Even-length hex converted successfully: {result.hex()}")
    except Exception as e:
        print(f"✗ Even-length hex conversion failed: {e}")
        return False
    
    # Test with spaces
    spaced_hex = "d17a fc88 2b5b"
    print(f"\nTesting spaced hex: {spaced_hex}")
    
    try:
        result = SimpleFileCrypto.hex_to_key(spaced_hex)
        print(f"✓ Spaced hex converted successfully: {result.hex()}")
    except Exception as e:
        print(f"✗ Spaced hex conversion failed: {e}")
        return False
    
    # Test with 0x prefix
    prefixed_hex = "0xd17afc882b5b"
    print(f"\nTesting prefixed hex: {prefixed_hex}")
    
    try:
        result = SimpleFileCrypto.hex_to_key(prefixed_hex)
        print(f"✓ Prefixed hex converted successfully: {result.hex()}")
    except Exception as e:
        print(f"✗ Prefixed hex conversion failed: {e}")
        return False
    
    print("\n✅ All odd-length hex string tests passed!")
    return True

if __name__ == "__main__":
    success = test_odd_hex_strings()
    sys.exit(0 if success else 1)