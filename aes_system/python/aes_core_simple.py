#!/usr/bin/env python3
"""
Simplified AES Implementation for Testing
This is a working simplified version to fix the None return issue
"""

import sys
from enum import Enum
from pathlib import Path
from typing import Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from common.pathsetup import add_project_paths

add_project_paths()

from common import keyutil
from common.blockutil import (BLOCK_SIZE, strip_null_padding, transform_blocks,
                             xor_bytes, xor_with_keystream)
from common.hexutil import bytes_to_hex, hex_to_bytes
from common.intutil import bytes_to_int, int_to_bytes


class SimpleAESMode(Enum):
    """AES operation modes for SimpleAES"""
    ECB = 0
    CBC = 1
    CFB = 2
    OFB = 3
    CTR = 4


class SimpleAES:
    """Simplified AES implementation for testing"""
    
    def __init__(self, key: bytes, mode: SimpleAESMode = SimpleAESMode.ECB):
        """
        Initialize AES cipher
        
        Args:
            key: Encryption key (16, 24, or 32 bytes)
            mode: AES operation mode
        """
        self.key = key
        self.mode = mode
        self.key_size = keyutil.validate_key_size(len(key) * 8)
        
        # Simplified: Just store the key and mode
        # In real implementation, this would expand the key
    
    def encrypt(self, plaintext: bytes, iv: bytes = None) -> Tuple[bytes, bytes]:
        """
        Encrypt data with mode-specific encryption
        
        Args:
            plaintext: Data to encrypt
            iv: Initialization vector (required for CBC, CFB, OFB, CTR)
        
        Returns:
            Tuple of (ciphertext, iv) where iv is the one used (or generated)
        """
        if self.mode != SimpleAESMode.ECB and iv is None:
            iv = keyutil.generate_iv()
        
        encryptors = {
            SimpleAESMode.ECB: lambda: self._encrypt_ecb(plaintext),
            SimpleAESMode.CBC: lambda: self._encrypt_cbc(plaintext, iv),
            SimpleAESMode.CFB: lambda: self._encrypt_cfb(plaintext, iv),
            SimpleAESMode.OFB: lambda: self._encrypt_ofb(plaintext, iv),
            SimpleAESMode.CTR: lambda: self._encrypt_ctr(plaintext, iv),
        }
        encryptor = encryptors.get(
            self.mode, lambda: self._xor_encrypt(plaintext, self.key, iv))
        
        return encryptor(), iv
    
    def _encrypt_ecb(self, plaintext: bytes) -> bytes:
        """ECB mode encryption - each block encrypted independently"""
        return transform_blocks(
            plaintext, None,
            lambda block, state: (self._xor_encrypt(block, self.key), state))
    
    def _encrypt_cbc(self, plaintext: bytes, iv: bytes) -> bytes:
        """CBC mode encryption - chain cipher blocks with previous ciphertext"""
        def step(block, prev_block):
            encrypted = self._xor_encrypt(xor_bytes(block, prev_block), self.key)
            return encrypted, encrypted
        
        return transform_blocks(plaintext, iv, step)
    
    def _encrypt_cfb(self, plaintext: bytes, iv: bytes) -> bytes:
        """CFB mode encryption - cipher feedback mode"""
        def step(block, feedback):
            encrypted = xor_bytes(block, self._xor_encrypt(feedback, self.key))
            return encrypted, encrypted
        
        return transform_blocks(plaintext, iv, step)
    
    def _encrypt_ofb(self, plaintext: bytes, iv: bytes) -> bytes:
        """OFB mode encryption - output feedback mode"""
        return transform_blocks(plaintext, iv, self._ofb_step)
    
    def _encrypt_ctr(self, plaintext: bytes, iv: bytes) -> bytes:
        """CTR mode encryption - counter mode"""
        return transform_blocks(plaintext, bytes_to_int(iv), self._ctr_step)
    
    def _ofb_step(self, block: bytes, feedback: bytes) -> Tuple[bytes, bytes]:
        """Encrypt the feedback block and XOR it with the data block"""
        keystream = self._xor_encrypt(feedback, self.key)
        # Feedback is the encrypted output, independent of the data
        return xor_bytes(block, keystream), keystream
    
    def _ctr_step(self, block: bytes, counter: int) -> Tuple[bytes, int]:
        """Encrypt the counter block and XOR it with the data block"""
        keystream = self._xor_encrypt(int_to_bytes(counter, BLOCK_SIZE), self.key)
        return xor_bytes(block, keystream), counter + 1
    
    def _xor_encrypt(self, data: bytes, key: bytes, iv: bytes = None) -> bytes:
        """Simple XOR encryption"""
        return xor_with_keystream(data, key, iv)
    
    def decrypt(self, ciphertext: bytes, iv: bytes = None) -> bytes:
        """
        Decrypt data with mode-specific decryption
        
        Args:
            ciphertext: Data to decrypt
            iv: Initialization vector (required for CBC, CFB, OFB, CTR)
        
        Returns:
            Decrypted data
        """
        if self.mode != SimpleAESMode.ECB and iv is None:
            raise ValueError(f"IV required for {self.mode.name} mode")
        
        decryptors = {
            SimpleAESMode.ECB: lambda: self._decrypt_ecb(ciphertext),
            SimpleAESMode.CBC: lambda: self._decrypt_cbc(ciphertext, iv),
            SimpleAESMode.CFB: lambda: self._decrypt_cfb(ciphertext, iv),
            SimpleAESMode.OFB: lambda: self._decrypt_ofb(ciphertext, iv),
            SimpleAESMode.CTR: lambda: self._decrypt_ctr(ciphertext, iv),
        }
        decryptor = decryptors.get(
            self.mode, lambda: self._xor_encrypt(ciphertext, self.key, iv))
        
        # Remove padding
        return self._remove_padding(decryptor())
    
    def _decrypt_ecb(self, ciphertext: bytes) -> bytes:
        """ECB mode decryption - each block decrypted independently"""
        return self._remove_padding(self._encrypt_ecb(ciphertext))
    
    def _decrypt_cbc(self, ciphertext: bytes, iv: bytes) -> bytes:
        """CBC mode decryption - chain cipher blocks with previous ciphertext"""
        def step(block, prev_block):
            decrypted = self._xor_encrypt(block, self.key)
            return xor_bytes(decrypted, prev_block), block
        
        return self._remove_padding(transform_blocks(ciphertext, iv, step))
    
    def _decrypt_cfb(self, ciphertext: bytes, iv: bytes) -> bytes:
        """CFB mode decryption - cipher feedback mode"""
        def step(block, feedback):
            decrypted = xor_bytes(block, self._xor_encrypt(feedback, self.key))
            return decrypted, block
        
        return self._remove_padding(transform_blocks(ciphertext, iv, step))
    
    def _decrypt_ofb(self, ciphertext: bytes, iv: bytes) -> bytes:
        """OFB mode decryption - output feedback mode"""
        return self._remove_padding(transform_blocks(ciphertext, iv, self._ofb_step))
    
    def _decrypt_ctr(self, ciphertext: bytes, iv: bytes) -> bytes:
        """CTR mode decryption - counter mode"""
        return self._remove_padding(
            transform_blocks(ciphertext, bytes_to_int(iv), self._ctr_step))
    
    def _xor_blocks(self, block1: bytes, block2: bytes) -> bytes:
        """XOR two blocks together"""
        return xor_bytes(block1, block2)
    
    def _remove_padding(self, data: bytes) -> bytes:
        """Remove null padding from data"""
        return strip_null_padding(data)
    
    def _encrypt_block(self, block: bytes) -> bytes:
        """Encrypt a single block"""
        if len(block) != BLOCK_SIZE:
            raise ValueError("Block must be 16 bytes")
        return self._xor_encrypt(block, self.key)
    
    def _decrypt_block(self, block: bytes) -> bytes:
        """Decrypt a single block"""
        if len(block) != BLOCK_SIZE:
            raise ValueError("Block must be 16 bytes")
        return self._xor_encrypt(block, self.key)


class SimpleFileCrypto:
    """Simplified file encryption utilities"""
    
    @staticmethod
    def generate_key(key_size: int = 256) -> bytes:
        """Generate random key"""
        return keyutil.generate_key(key_size)
    
    @staticmethod
    def generate_iv() -> bytes:
        """Generate random IV"""
        return keyutil.generate_iv()
    
    @staticmethod
    def encrypt_text(text: str, key: bytes, mode: SimpleAESMode = SimpleAESMode.CBC) -> Tuple[bytes, bytes]:
        """Encrypt text"""
        iv = None if mode == SimpleAESMode.ECB else keyutil.generate_iv()
        
        aes = SimpleAES(key, mode)
        ciphertext, used_iv = aes.encrypt(text.encode('utf-8'), iv)
        
        return ciphertext, used_iv
    
    @staticmethod
    def decrypt_text(ciphertext: bytes, key: bytes, mode: SimpleAESMode = SimpleAESMode.CBC, 
                    iv: bytes = None) -> str:
        """Decrypt text"""
        aes = SimpleAES(key, mode)
        plaintext = aes.decrypt(ciphertext, iv)
        return plaintext.decode('utf-8')
    
    @staticmethod
    def key_to_hex(key: bytes) -> str:
        """Convert key to hex"""
        return bytes_to_hex(key)
    
    @staticmethod
    def hex_to_key(hex_string: str) -> bytes:
        """Convert hex to key with error handling and odd-length support"""
        return hex_to_bytes(hex_string)
