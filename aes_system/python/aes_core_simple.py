#!/usr/bin/env python3
"""
Simplified AES Implementation for Testing
This is a working simplified version to fix the None return issue
"""

import os
from typing import List, Tuple
from enum import Enum


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
        self.key_size = len(key) * 8
        
        if self.key_size not in [128, 192, 256]:
            raise ValueError("Key must be 128, 192, or 256 bits")
        
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
        # Mode-specific encryption requirements
        if self.mode == SimpleAESMode.CBC and iv is None:
            iv = SimpleFileCrypto.generate_iv()
        if self.mode == SimpleAESMode.CFB and iv is None:
            iv = SimpleFileCrypto.generate_iv()
        if self.mode == SimpleAESMode.OFB and iv is None:
            iv = SimpleFileCrypto.generate_iv()
        if self.mode == SimpleAESMode.CTR and iv is None:
            iv = SimpleFileCrypto.generate_iv()
        
        # Mode-specific encryption logic
        if self.mode == SimpleAESMode.ECB:
            # ECB: Encrypt each block independently
            ciphertext = self._encrypt_ecb(plaintext)
        elif self.mode == SimpleAESMode.CBC:
            # CBC: Chain cipher blocks with IV
            ciphertext = self._encrypt_cbc(plaintext, iv)
        elif self.mode == SimpleAESMode.CFB:
            # CFB: Cipher feedback mode
            ciphertext = self._encrypt_cfb(plaintext, iv)
        elif self.mode == SimpleAESMode.OFB:
            # OFB: Output feedback mode
            ciphertext = self._encrypt_ofb(plaintext, iv)
        elif self.mode == SimpleAESMode.CTR:
            # CTR: Counter mode
            ciphertext = self._encrypt_ctr(plaintext, iv)
        else:
            # Fallback to XOR encryption
            ciphertext = self._xor_encrypt(plaintext, self.key, iv)
        
        return ciphertext, iv
    
    def _encrypt_ecb(self, plaintext: bytes) -> bytes:
        """ECB mode encryption - each block encrypted independently"""
        # Split into 16-byte blocks
        blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]
        ciphertext = bytearray()
        
        for block in blocks:
            # Pad if necessary
            if len(block) < 16:
                block = block + b'\x00' * (16 - len(block))
            # Encrypt block (XOR with key for simplicity)
            encrypted = self._xor_encrypt(block, self.key)
            ciphertext.extend(encrypted)
        
        return bytes(ciphertext)
    
    def _encrypt_cbc(self, plaintext: bytes, iv: bytes) -> bytes:
        """CBC mode encryption - chain cipher blocks with previous ciphertext"""
        # Split into 16-byte blocks
        blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]
        ciphertext = bytearray()
        prev_block = iv
        
        for block in blocks:
            # Pad if necessary
            if len(block) < 16:
                block = block + b'\x00' * (16 - len(block))
            # XOR with previous ciphertext block, then encrypt
            xor_result = self._xor_blocks(block, prev_block)
            encrypted = self._xor_encrypt(xor_result, self.key)
            ciphertext.extend(encrypted)
            prev_block = encrypted
        
        return bytes(ciphertext)
    
    def _encrypt_cfb(self, plaintext: bytes, iv: bytes) -> bytes:
        """CFB mode encryption - cipher feedback mode"""
        # Split into 16-byte blocks
        blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]
        ciphertext = bytearray()
        feedback = iv
        
        for block in blocks:
            # Pad if necessary
            if len(block) < 16:
                block = block + b'\x00' * (16 - len(block))
            # Encrypt feedback, XOR with plaintext
            encrypted_feedback = self._xor_encrypt(feedback, self.key)
            encrypted = self._xor_blocks(block, encrypted_feedback)
            ciphertext.extend(encrypted)
            feedback = encrypted
        
        return bytes(ciphertext)
    
    def _encrypt_ofb(self, plaintext: bytes, iv: bytes) -> bytes:
        """OFB mode encryption - output feedback mode"""
        # Split into 16-byte blocks
        blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]
        ciphertext = bytearray()
        feedback = iv
        
        for block in blocks:
            # Pad if necessary
            if len(block) < 16:
                block = block + b'\x00' * (16 - len(block))
            # Encrypt feedback, XOR with plaintext
            encrypted_feedback = self._xor_encrypt(feedback, self.key)
            encrypted = self._xor_blocks(block, encrypted_feedback)
            ciphertext.extend(encrypted)
            feedback = encrypted_feedback  # Feedback is encrypted output
            
        return bytes(ciphertext)
    
    def _encrypt_ctr(self, plaintext: bytes, iv: bytes) -> bytes:
        """CTR mode encryption - counter mode"""
        # Split into 16-byte blocks
        blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]
        ciphertext = bytearray()
        counter = int.from_bytes(iv, byteorder='big')
        
        for block in blocks:
            # Pad if necessary
            if len(block) < 16:
                block = block + b'\x00' * (16 - len(block))
            # Encrypt counter, XOR with plaintext
            counter_bytes = counter.to_bytes(16, byteorder='big')
            encrypted_counter = self._xor_encrypt(counter_bytes, self.key)
            encrypted = self._xor_blocks(block, encrypted_counter)
            ciphertext.extend(encrypted)
            counter += 1
        
        return bytes(ciphertext)
    
    def _xor_encrypt(self, data: bytes, key: bytes, iv: bytes = None) -> bytes:
        """Simple XOR encryption"""
        result = bytearray(len(data))
        key_expanded = (key * ((len(data) // len(key)) + 1))[:len(data)]
        
        if iv is not None:
            iv_expanded = (iv * ((len(data) // len(iv)) + 1))[:len(data)]
            for i in range(len(data)):
                result[i] = data[i] ^ key_expanded[i] ^ iv_expanded[i]
        else:
            for i in range(len(data)):
                result[i] = data[i] ^ key_expanded[i]
        
        return bytes(result)
    
    def decrypt(self, ciphertext: bytes, iv: bytes = None) -> bytes:
        """
        Decrypt data with mode-specific decryption
        
        Args:
            ciphertext: Data to decrypt
            iv: Initialization vector (required for CBC, CFB, OFB, CTR)
        
        Returns:
            Decrypted data
        """
        # Mode-specific decryption requirements
        if self.mode == SimpleAESMode.CBC and iv is None:
            raise ValueError("IV required for CBC mode")
        if self.mode == SimpleAESMode.CFB and iv is None:
            raise ValueError("IV required for CFB mode")
        if self.mode == SimpleAESMode.OFB and iv is None:
            raise ValueError("IV required for OFB mode")
        if self.mode == SimpleAESMode.CTR and iv is None:
            raise ValueError("IV required for CTR mode")
        
        # Mode-specific decryption logic
        if self.mode == SimpleAESMode.ECB:
            # ECB: Decrypt each block independently
            decrypted = self._decrypt_ecb(ciphertext)
        elif self.mode == SimpleAESMode.CBC:
            # CBC: Chain cipher blocks with IV
            decrypted = self._decrypt_cbc(ciphertext, iv)
        elif self.mode == SimpleAESMode.CFB:
            # CFB: Cipher feedback mode
            decrypted = self._decrypt_cfb(ciphertext, iv)
        elif self.mode == SimpleAESMode.OFB:
            # OFB: Output feedback mode
            decrypted = self._decrypt_ofb(ciphertext, iv)
        elif self.mode == SimpleAESMode.CTR:
            # CTR: Counter mode
            decrypted = self._decrypt_ctr(ciphertext, iv)
        else:
            # Fallback to XOR decryption
            decrypted = self._xor_encrypt(ciphertext, self.key, iv)
        
        # Remove padding
        return self._remove_padding(decrypted)
    
    def _decrypt_ecb(self, ciphertext: bytes) -> bytes:
        """ECB mode decryption - each block decrypted independently"""
        # Split into 16-byte blocks
        blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
        plaintext = bytearray()
        
        for block in blocks:
            # Pad if necessary
            if len(block) < 16:
                block = block + b'\x00' * (16 - len(block))
            # Decrypt block (XOR with key for simplicity)
            decrypted = self._xor_encrypt(block, self.key)
            plaintext.extend(decrypted)
        
        return self._remove_padding(bytes(plaintext))
    
    def _decrypt_cbc(self, ciphertext: bytes, iv: bytes) -> bytes:
        """CBC mode decryption - chain cipher blocks with previous ciphertext"""
        # Split into 16-byte blocks
        blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
        plaintext = bytearray()
        prev_block = iv
        
        for block in blocks:
            # Pad if necessary
            if len(block) < 16:
                block = block + b'\x00' * (16 - len(block))
            # Decrypt block and XOR with previous ciphertext block
            decrypted = self._xor_encrypt(block, self.key)
            xor_result = self._xor_blocks(decrypted, prev_block)
            plaintext.extend(xor_result)
            prev_block = block
        
        return self._remove_padding(bytes(plaintext))
    
    def _decrypt_cfb(self, ciphertext: bytes, iv: bytes) -> bytes:
        """CFB mode decryption - cipher feedback mode"""
        # Split into 16-byte blocks
        blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
        plaintext = bytearray()
        feedback = iv
        
        for block in blocks:
            # Pad if necessary
            if len(block) < 16:
                block = block + b'\x00' * (16 - len(block))
            # Encrypt feedback, XOR with ciphertext
            encrypted_feedback = self._xor_encrypt(feedback, self.key)
            decrypted = self._xor_blocks(block, encrypted_feedback)
            plaintext.extend(decrypted)
            feedback = block
        
        return self._remove_padding(bytes(plaintext))
    
    def _decrypt_ofb(self, ciphertext: bytes, iv: bytes) -> bytes:
        """OFB mode decryption - output feedback mode"""
        # Split into 16-byte blocks
        blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
        plaintext = bytearray()
        feedback = iv
        
        for block in blocks:
            # Pad if necessary
            if len(block) < 16:
                block = block + b'\x00' * (16 - len(block))
            # Encrypt feedback, XOR with ciphertext
            encrypted_feedback = self._xor_encrypt(feedback, self.key)
            decrypted = self._xor_blocks(block, encrypted_feedback)
            plaintext.extend(decrypted)
            feedback = encrypted_feedback  # Feedback is encrypted output
            
        return self._remove_padding(bytes(plaintext))
    
    def _decrypt_ctr(self, ciphertext: bytes, iv: bytes) -> bytes:
        """CTR mode decryption - counter mode"""
        # Split into 16-byte blocks
        blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
        plaintext = bytearray()
        counter = int.from_bytes(iv, byteorder='big')
        
        for block in blocks:
            # Pad if necessary
            if len(block) < 16:
                block = block + b'\x00' * (16 - len(block))
            # Encrypt counter, XOR with ciphertext
            counter_bytes = counter.to_bytes(16, byteorder='big')
            encrypted_counter = self._xor_encrypt(counter_bytes, self.key)
            decrypted = self._xor_blocks(block, encrypted_counter)
            plaintext.extend(decrypted)
            counter += 1
        
        return self._remove_padding(bytes(plaintext))
    
    def _xor_blocks(self, block1: bytes, block2: bytes) -> bytes:
        """XOR two blocks together"""
        result = bytearray(len(block1))
        for i in range(len(block1)):
            result[i] = block1[i] ^ block2[i]
        return bytes(result)
    
    def _remove_padding(self, data: bytes) -> bytes:
        """Remove null padding from data"""
        # Remove trailing null bytes
        return data.rstrip(b'\x00')
    
    def _encrypt_block(self, block: bytes) -> bytes:
        """Encrypt a single block"""
        if len(block) != 16:
            raise ValueError("Block must be 16 bytes")
        return self._xor_encrypt(block, self.key)
    
    def _decrypt_block(self, block: bytes) -> bytes:
        """Decrypt a single block"""
        if len(block) != 16:
            raise ValueError("Block must be 16 bytes")
        return self._xor_encrypt(block, self.key)


class SimpleFileCrypto:
    """Simplified file encryption utilities"""
    
    @staticmethod
    def generate_key(key_size: int = 256) -> bytes:
        """Generate random key"""
        if key_size not in [128, 192, 256]:
            raise ValueError("Key size must be 128, 192, or 256 bits")
        return os.urandom(key_size // 8)
    
    @staticmethod
    def generate_iv() -> bytes:
        """Generate random IV"""
        return os.urandom(16)
    
    @staticmethod
    def encrypt_text(text: str, key: bytes, mode: SimpleAESMode = SimpleAESMode.CBC) -> Tuple[bytes, bytes]:
        """Encrypt text"""
        plaintext = text.encode('utf-8')
        
        if mode != SimpleAESMode.ECB:
            iv = SimpleFileCrypto.generate_iv()
        else:
            iv = None
        
        aes = SimpleAES(key, mode)
        ciphertext, used_iv = aes.encrypt(plaintext, iv)
        
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
        return key.hex()
    
    @staticmethod
    def hex_to_key(hex_string: str) -> bytes:
        """Convert hex to key with error handling and odd-length support"""
        # Remove common formatting issues
        hex_string = hex_string.strip()
        # Remove spaces, newlines, and other whitespace
        hex_string = ''.join(hex_string.split())
        # Remove '0x' prefix if present
        if hex_string.startswith('0x'):
            hex_string = hex_string[2:]
        # Handle empty string
        if not hex_string:
            raise ValueError("Empty hex string")
        # Handle odd-length hex strings by padding with leading zero
        if len(hex_string) % 2 != 0:
            hex_string = '0' + hex_string
        return bytes.fromhex(hex_string)