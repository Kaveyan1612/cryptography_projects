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


def _to_simple_mode(mode: AESMode) -> SimpleAESMode:
    """
    Translate an AESMode into the equivalent SimpleAESMode

    Raises:
        TypeError: if mode is not an AESMode
        ValueError: if the mode has no SimpleAES equivalent
    """
    if not isinstance(mode, AESMode):
        raise TypeError(f"Mode must be an AESMode, got {mode!r}")
    try:
        return SimpleAESMode[mode.name]
    except KeyError as e:
        raise ValueError(f"Unsupported AES mode: {mode.name}") from e


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
                    mode: AESMode = AESMode.CBC) -> Tuple[bytes, bytes]:
        """
        Encrypt a file
        
        Args:
            input_file: Path to input file
            output_file: Path to output file
            key: AES key
            mode: AES mode
        
        Returns:
            Tuple of (key, iv) used for encryption
        """
        simple_mode = _to_simple_mode(mode)
        
        # Read input file
        with open(input_file, 'rb') as f:
            plaintext = f.read()
        
        # Generate IV if needed
        if mode != AESMode.ECB:
            iv = FileCrypto.generate_iv()
        else:
            iv = None
        
        # Encrypt using SimpleAES
        aes = SimpleAES(key, simple_mode)
        ciphertext, used_iv = aes.encrypt(plaintext, iv)
        
        # Write output file only once encryption succeeded
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
        simple_mode = _to_simple_mode(mode)
        
        # Read input file
        with open(input_file, 'rb') as f:
            ciphertext = f.read()
        
        # Decrypt using SimpleAES
        aes = SimpleAES(key, simple_mode)
        plaintext = aes.decrypt(ciphertext, iv)
        
        # Write output file only once decryption succeeded
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
        return SimpleFileCrypto.encrypt_text(text, key, _to_simple_mode(mode))
    
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
        return SimpleFileCrypto.decrypt_text(ciphertext, key, _to_simple_mode(mode), iv)
    
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
        simple_mode = _to_simple_mode(mode)
        
        if mode != AESMode.ECB:
            iv = FileCrypto.generate_iv()
        else:
            iv = None
        
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
        aes = SimpleAES(key, _to_simple_mode(mode))
        return aes.decrypt(ciphertext, iv)
    
    @staticmethod
    def save_key(key: bytes, filename: str) -> None:
        """
        Save key to file
        
        Args:
            key: Key to save
            filename: Output filename
        """
        with open(filename, 'wb') as f:
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
            key = f.read()
        
        if len(key) * 8 not in [128, 192, 256]:
            raise ValueError(
                f"Key file '{filename}' does not contain a 128, 192 or 256-bit key "
                f"(got {len(key)} bytes)"
            )
        
        return key
    
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