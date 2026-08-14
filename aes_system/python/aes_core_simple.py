#!/usr/bin/env python3
"""
AES implementation backed by the audited `cryptography` library.

This module provides the same API the GUI and file utilities use, but every
operation is real AES (FIPS-197) rather than a toy transformation.
"""

import os
import warnings
from typing import Optional, Tuple
from enum import Enum

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


BLOCK_SIZE = 16


class SimpleAESMode(Enum):
    """AES operation modes for SimpleAES"""
    ECB = 0
    CBC = 1
    CFB = 2
    OFB = 3
    CTR = 4


# Alias kept for callers importing AESMode from this module
AESMode = SimpleAESMode

# Modes that operate on whole blocks and therefore require padding
BLOCK_MODES = (SimpleAESMode.ECB, SimpleAESMode.CBC)


class SimpleAES:
    """AES cipher supporting ECB, CBC, CFB, OFB and CTR modes"""

    def __init__(self, key: bytes, mode: SimpleAESMode = SimpleAESMode.CBC):
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

        if mode == SimpleAESMode.ECB:
            warnings.warn(
                "ECB mode leaks plaintext structure and must not be used to "
                "protect real data; prefer CBC or CTR with a random IV.",
                stacklevel=2,
            )

    def _cipher(self, iv: Optional[bytes]) -> Cipher:
        """Build the underlying AES cipher for the configured mode"""
        algorithm = algorithms.AES(self.key)

        if self.mode == SimpleAESMode.ECB:
            return Cipher(algorithm, modes.ECB())

        if iv is None:
            raise ValueError(f"IV required for {self.mode.name} mode")
        if len(iv) != BLOCK_SIZE:
            raise ValueError("IV must be 16 bytes")

        mode_map = {
            SimpleAESMode.CBC: modes.CBC,
            SimpleAESMode.CFB: modes.CFB,
            SimpleAESMode.OFB: modes.OFB,
            SimpleAESMode.CTR: modes.CTR,
        }
        try:
            block_mode = mode_map[self.mode]
        except KeyError:
            raise ValueError(f"Unsupported mode: {self.mode}") from None

        return Cipher(algorithm, block_mode(iv))

    def encrypt(self, plaintext: bytes, iv: bytes = None) -> Tuple[bytes, bytes]:
        """
        Encrypt data

        Args:
            plaintext: Data to encrypt
            iv: Initialization vector (generated if omitted for non-ECB modes)

        Returns:
            Tuple of (ciphertext, iv) where iv is the one used (or generated)
        """
        if self.mode != SimpleAESMode.ECB and iv is None:
            iv = SimpleFileCrypto.generate_iv()

        if self.mode in BLOCK_MODES:
            plaintext = self._pad(plaintext)

        encryptor = self._cipher(iv).encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        return ciphertext, iv

    def decrypt(self, ciphertext: bytes, iv: bytes = None) -> bytes:
        """
        Decrypt data

        Args:
            ciphertext: Data to decrypt
            iv: Initialization vector (required for CBC, CFB, OFB, CTR)

        Returns:
            Decrypted data
        """
        if self.mode in BLOCK_MODES and len(ciphertext) % BLOCK_SIZE != 0:
            raise ValueError("Ciphertext length must be a multiple of 16 bytes")

        decryptor = self._cipher(iv).decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        if self.mode in BLOCK_MODES:
            plaintext = self._unpad(plaintext)
        return plaintext

    @staticmethod
    def _pad(data: bytes) -> bytes:
        """Apply PKCS#7 padding"""
        padding_length = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
        return data + bytes([padding_length] * padding_length)

    @staticmethod
    def _unpad(data: bytes) -> bytes:
        """Strip and validate PKCS#7 padding"""
        if not data or len(data) % BLOCK_SIZE != 0:
            raise ValueError("Invalid padded data length")
        padding_length = data[-1]
        if not 1 <= padding_length <= BLOCK_SIZE:
            raise ValueError("Invalid padding")
        if data[-padding_length:] != bytes([padding_length] * padding_length):
            raise ValueError("Invalid padding")
        return data[:-padding_length]

    def _encrypt_block(self, block: bytes) -> bytes:
        """Encrypt a single 16-byte block with the raw block cipher"""
        if len(block) != BLOCK_SIZE:
            raise ValueError("Block must be 16 bytes")
        encryptor = Cipher(algorithms.AES(self.key), modes.ECB()).encryptor()
        return encryptor.update(block) + encryptor.finalize()

    def _decrypt_block(self, block: bytes) -> bytes:
        """Decrypt a single 16-byte block with the raw block cipher"""
        if len(block) != BLOCK_SIZE:
            raise ValueError("Block must be 16 bytes")
        decryptor = Cipher(algorithms.AES(self.key), modes.ECB()).decryptor()
        return decryptor.update(block) + decryptor.finalize()


class SimpleFileCrypto:
    """File encryption utilities"""

    @staticmethod
    def generate_key(key_size: int = 256) -> bytes:
        """Generate random key using the OS CSPRNG"""
        if key_size not in [128, 192, 256]:
            raise ValueError("Key size must be 128, 192, or 256 bits")
        return os.urandom(key_size // 8)

    @staticmethod
    def generate_iv() -> bytes:
        """Generate random IV using the OS CSPRNG"""
        return os.urandom(BLOCK_SIZE)

    @staticmethod
    def encrypt_text(text: str, key: bytes,
                     mode: SimpleAESMode = SimpleAESMode.CBC) -> Tuple[bytes, bytes]:
        """Encrypt text"""
        aes = SimpleAES(key, mode)
        return aes.encrypt(text.encode('utf-8'))

    @staticmethod
    def decrypt_text(ciphertext: bytes, key: bytes, mode: SimpleAESMode = SimpleAESMode.CBC,
                     iv: bytes = None) -> str:
        """Decrypt text"""
        aes = SimpleAES(key, mode)
        return aes.decrypt(ciphertext, iv).decode('utf-8')

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
