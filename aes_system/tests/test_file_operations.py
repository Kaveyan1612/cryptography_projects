#!/usr/bin/env python3
"""
Test file encryption/decryption operations
"""

import sys
import os
import tempfile

# Add python directory to path
python_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'python')
sys.path.insert(0, python_dir)

from file_crypto import FileCrypto
from aes_core import AESMode

def test_file_operations():
    """Test file encryption and decryption"""
    print("Testing file encryption/decryption operations...")
    
    # Create temporary files
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        input_file = f.name
        f.write("This is a test file for AES encryption/decryption.")
    
    encrypted_file = input_file + '.enc'
    decrypted_file = input_file + '.dec'
    
    try:
        # Generate key
        key = FileCrypto.generate_key(256)
        print(f"✓ Key generated: {key.hex()[:32]}...")
        
        # Test file encryption
        print(f"\nEncrypting file: {input_file}")
        enc_key, iv = FileCrypto.encrypt_file(input_file, encrypted_file, key, AESMode.CBC)
        print(f"✓ File encrypted successfully")
        print(f"  IV: {iv.hex()[:32]}...")
        
        # Verify encrypted file exists
        if os.path.exists(encrypted_file):
            print(f"✓ Encrypted file created: {encrypted_file}")
            file_size = os.path.getsize(encrypted_file)
            print(f"  File size: {file_size} bytes")
        else:
            print(f"✗ Encrypted file not created")
            return False
        
        # Test file decryption
        print(f"\nDecrypting file: {encrypted_file}")
        FileCrypto.decrypt_file(encrypted_file, decrypted_file, key, AESMode.CBC, iv)
        print(f"✓ File decrypted successfully")
        
        # Verify decrypted file exists
        if os.path.exists(decrypted_file):
            print(f"✓ Decrypted file created: {decrypted_file}")
        else:
            print(f"✗ Decrypted file not created")
            return False
        
        # Verify content
        with open(input_file, 'r') as f:
            original_content = f.read()
        
        with open(decrypted_file, 'r') as f:
            decrypted_content = f.read()
        
        if original_content == decrypted_content:
            print(f"✓ Content verification passed")
            print(f"  Original: {original_content[:50]}...")
            print(f"  Decrypted: {decrypted_content[:50]}...")
        else:
            print(f"✗ Content verification failed")
            print(f"  Original: {original_content}")
            print(f"  Decrypted: {decrypted_content}")
            return False
        
        # Test with different modes
        modes_to_test = [AESMode.ECB, AESMode.CFB, AESMode.OFB, AESMode.CTR]
        
        for mode in modes_to_test:
            print(f"\nTesting {mode.name} mode...")
            
            try:
                enc_key, iv = FileCrypto.encrypt_file(input_file, encrypted_file, key, mode)
                FileCrypto.decrypt_file(encrypted_file, decrypted_file, key, mode, iv)
                
                with open(decrypted_file, 'r') as f:
                    decrypted_content = f.read()
                
                if original_content == decrypted_content:
                    print(f"✓ {mode.name} mode works correctly")
                else:
                    print(f"✗ {mode.name} mode failed")
                    return False
                    
            except Exception as e:
                print(f"✗ {mode.name} mode failed: {e}")
                import traceback
                traceback.print_exc()
                return False
        
        print("\n✅ All file operation tests passed!")
        return True
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Clean up temporary files
        for file_path in [input_file, encrypted_file, decrypted_file]:
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    print(f"Cleaned up: {file_path}")
                except Exception as e:
                    print(f"Failed to clean up {file_path}: {e}")

if __name__ == "__main__":
    success = test_file_operations()
    sys.exit(0 if success else 1)