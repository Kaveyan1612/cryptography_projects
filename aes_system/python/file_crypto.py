#!/usr/bin/env python3
"""
File encryption/decryption utilities for AES
"""

import sys
from pathlib import Path
from typing import Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from common.pathsetup import add_project_paths

add_project_paths()

from common import keyutil
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
        keyutil.validate_key_size(key_size)
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
    def _cipher(key: bytes, mode: AESMode) -> SimpleAES:
        """Build a SimpleAES cipher for the equivalent simplified mode"""
        return SimpleAES(key, SimpleAESMode[mode.name])
    
    @staticmethod
    def _iv_for_mode(mode: AESMode) -> Optional[bytes]:
        """Generate an IV for every mode except ECB"""
        return None if mode == AESMode.ECB else FileCrypto.generate_iv()
    
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
        plaintext = FileCrypto._read_file(input_file)
        ciphertext, used_iv = FileCrypto.encrypt_bytes(plaintext, key, mode)
        FileCrypto._write_file(output_file, ciphertext)
        
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
        ciphertext = FileCrypto._read_file(input_file)
        plaintext = FileCrypto.decrypt_bytes(ciphertext, key, mode, iv)
        FileCrypto._write_file(output_file, plaintext)
    
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
        return SimpleFileCrypto.encrypt_text(text, key, SimpleAESMode[mode.name])
    
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
        return SimpleFileCrypto.decrypt_text(
            ciphertext, key, SimpleAESMode[mode.name], iv)
    
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
        return FileCrypto._cipher(key, mode).encrypt(
            data, FileCrypto._iv_for_mode(mode))
    
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
        return FileCrypto._cipher(key, mode).decrypt(ciphertext, iv)
    
    @staticmethod
    def _read_file(filename: str) -> bytes:
        """Read a file in binary mode"""
        with open(filename, 'rb') as f:
            return f.read()
    
    @staticmethod
    def _write_file(filename: str, data: bytes) -> None:
        """Write a file in binary mode"""
        with open(filename, 'wb') as f:
            f.write(data)
    
    @staticmethod
    def save_key(key: bytes, filename: str) -> None:
        """
        Save key to file
        
        Args:
            key: Key to save
            filename: Output filename
        """
        FileCrypto._write_file(filename, key)
    
    @staticmethod
    def load_key(filename: str) -> bytes:
        """
        Load key from file
        
        Args:
            filename: Input filename
        
        Returns:
            Loaded key
        """
        return FileCrypto._read_file(filename)
    
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