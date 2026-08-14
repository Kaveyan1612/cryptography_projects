#!/usr/bin/env python3
"""
File encryption/decryption utilities for AES
"""

import os
import sys
from typing import Tuple

# Ensure we can import from the same directory
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from aes_core import AES, AESMode
from aes_core_simple import SimpleAES, SimpleFileCrypto, SimpleAESMode


class FileCrypto:
    """File encryption and decryption using AES"""
    
    @staticmethod
    def generate_key(key_size: int = 256) -> bytes:
        """
        Generate random AES key
        
        Args:
            key_size: Key size in bits (128, 192, 256)
        
        Returns:
            Random key
        """
        if key_size not in [128, 192, 256]:
            raise ValueError("Key size must be 128, 192, or 256 bits")
        return SimpleFileCrypto.generate_key(key_size)
    
    @staticmethod
    def generate_iv() -> bytes:
        """
        Generate random initialization vector
        
        Returns:
            Random 16-byte IV
        """
        return SimpleFileCrypto.generate_iv()
    
    @staticmethod
    def encrypt_file(input_file: str, output_file: str, key: bytes, 
                    mode: AESMode = AESMode.CBC, iv: bytes = None) -> Tuple[bytes, bytes]:
        """
        Encrypt a file
        
        Args:
            input_file: Path to input file
            output_file: Path to output file
            key: AES key
            mode: AES mode
            iv: Initialization vector (generated if omitted for non-ECB modes)
        
        Returns:
            Tuple of (key, iv) used for encryption
        """
        # Read input file
        with open(input_file, 'rb') as f:
            plaintext = f.read()
        
        # Generate IV if needed
        if mode == AESMode.ECB:
            iv = None
        elif iv is None:
            iv = FileCrypto.generate_iv()
        
        # Encrypt using SimpleAES
        # Convert AESMode to SimpleAESMode
        simple_mode = SimpleAESMode[mode.name]
        aes = SimpleAES(key, simple_mode)
        ciphertext, used_iv = aes.encrypt(plaintext, iv)
        
        # Write output file
        with open(output_file, 'wb') as f:
            f.write(ciphertext)
        
        return key, used_iv
    
    @staticmethod
    def decrypt_file(input_file: str, output_file: str, key: bytes, 
                    mode: AESMode = AESMode.CBC, iv: bytes = None) -> None:
        """
        Decrypt a file
        
        Args:
            input_file: Path to input file
            output_file: Path to output file
            key: AES key
            mode: AES mode
            iv: Initialization vector (required for most modes)
        """
        # Read input file
        with open(input_file, 'rb') as f:
            ciphertext = f.read()
        
        # Decrypt using SimpleAES
        # Convert AESMode to SimpleAESMode
        simple_mode = SimpleAESMode[mode.name]
        aes = SimpleAES(key, simple_mode)
        plaintext = aes.decrypt(ciphertext, iv)
        
        # Write output file
        with open(output_file, 'wb') as f:
            f.write(plaintext)
    
    @staticmethod
    def encrypt_text(text: str, key: bytes, mode: AESMode = AESMode.CBC) -> Tuple[bytes, bytes]:
        """
        Encrypt text string
        
        Args:
            text: Text to encrypt
            key: AES key
            mode: AES mode
        
        Returns:
            Tuple of (ciphertext, iv)
        """
        # Convert AESMode to SimpleAESMode
        simple_mode = SimpleAESMode[mode.name]
        return SimpleFileCrypto.encrypt_text(text, key, simple_mode)
    
    @staticmethod
    def decrypt_text(ciphertext: bytes, key: bytes, mode: AESMode = AESMode.CBC, 
                    iv: bytes = None) -> str:
        """
        Decrypt text string
        
        Args:
            ciphertext: Ciphertext to decrypt
            key: AES key
            mode: AES mode
            iv: Initialization vector
        
        Returns:
            Decrypted text string
        """
        # Convert AESMode to SimpleAESMode
        simple_mode = SimpleAESMode[mode.name]
        return SimpleFileCrypto.decrypt_text(ciphertext, key, simple_mode, iv)
    
    @staticmethod
    def encrypt_bytes(data: bytes, key: bytes, mode: AESMode = AESMode.CBC) -> Tuple[bytes, bytes]:
        """
        Encrypt raw bytes
        
        Args:
            data: Data to encrypt
            key: AES key
            mode: AES mode
        
        Returns:
            Tuple of (ciphertext, iv)
        """
        plaintext = data
        
        if mode != AESMode.ECB:
            iv = FileCrypto.generate_iv()
        else:
            iv = None
        
        # Convert AESMode to SimpleAESMode
        simple_mode = SimpleAESMode[mode.name]
        aes = SimpleAES(key, simple_mode)
        ciphertext, used_iv = aes.encrypt(plaintext, iv)
        
        return ciphertext, used_iv
    
    @staticmethod
    def decrypt_bytes(ciphertext: bytes, key: bytes, mode: AESMode = AESMode.CBC, 
                    iv: bytes = None) -> bytes:
        """
        Decrypt raw bytes
        
        Args:
            ciphertext: Ciphertext to decrypt
            key: AES key
            mode: AES mode
            iv: Initialization vector
        
        Returns:
            Decrypted bytes
        """
        # Convert AESMode to SimpleAESMode
        simple_mode = SimpleAESMode[mode.name]
        aes = SimpleAES(key, simple_mode)
        return aes.decrypt(ciphertext, iv)
    
    @staticmethod
    def save_key(key: bytes, filename: str) -> None:
        """
        Save key to file
        
        Args:
            key: Key to save
            filename: Output filename
        """
        # Keys must not be world/group readable
        fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(key)
    
    @staticmethod
    def load_key(filename: str) -> bytes:
        """
        Load key from file
        
        Args:
            filename: Input filename
        
        Returns:
            Loaded key
        """
        with open(filename, 'rb') as f:
            return f.read()
    
    @staticmethod
    def key_to_hex(key: bytes) -> str:
        """
        Convert key to hexadecimal string
        
        Args:
            key: Key to convert
        
        Returns:
            Hexadecimal string
        """
        return SimpleFileCrypto.key_to_hex(key)
    
    @staticmethod
    def hex_to_key(hex_string: str) -> bytes:
        """
        Convert hexadecimal string to key
        
        Args:
            hex_string: Hexadecimal string
        
        Returns:
            Key bytes
        """
        return SimpleFileCrypto.hex_to_key(hex_string)