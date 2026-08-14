#!/usr/bin/env python3
"""
AES Encryption/Decryption Core Implementation
Implements AES-128, AES-192, AES-256 with various modes
"""

import os
import struct
import warnings
from typing import List, Optional
from enum import Enum


class AESMode(Enum):
    """AES operation modes"""
    ECB = 0
    CBC = 1
    CFB = 2
    OFB = 3
    CTR = 4


class AESKeySize(Enum):
    """AES key sizes"""
    AES_128 = 128
    AES_192 = 192
    AES_256 = 256


# Modes that operate on whole blocks and therefore require padding
BLOCK_MODES = (AESMode.ECB, AESMode.CBC)

BLOCK_SIZE = 16


def _build_s_box() -> List[int]:
    """Build the AES S-Box from the multiplicative inverse in GF(2^8)"""
    p = q = 1
    inverse = [0] * 256
    while True:
        # p *= 3
        p = p ^ ((p << 1) & 0xff) ^ (0x1b if p & 0x80 else 0)
        # q /= 3
        q ^= (q << 1) & 0xff
        q ^= (q << 2) & 0xff
        q ^= (q << 4) & 0xff
        if q & 0x80:
            q ^= 0x09
        inverse[p] = q
        if p == 1:
            break

    s_box = [0] * 256
    for i in range(256):
        inv = inverse[i]
        value = inv
        for shift in (1, 2, 3, 4):
            value ^= ((inv << shift) | (inv >> (8 - shift))) & 0xff
        s_box[i] = value ^ 0x63
    return s_box


class AES:
    """AES encryption/decryption implementation"""

    # S-Box for SubBytes / inverse S-Box for InvSubBytes
    S_BOX = _build_s_box()
    INV_S_BOX = [0] * 256
    for _index, _value in enumerate(S_BOX):
        INV_S_BOX[_value] = _index
    del _index, _value

    # Round constants for KeyExpansion
    R_CON = [
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
        0x6c, 0xd8, 0xab, 0x4d
    ]

    def __init__(self, key: bytes, mode: AESMode = AESMode.CBC):
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

        if mode == AESMode.ECB:
            warnings.warn(
                "ECB mode leaks plaintext structure and must not be used to "
                "protect real data; prefer CBC or CTR with a random IV.",
                stacklevel=2,
            )

        self.rounds = {128: 10, 192: 12, 256: 14}[self.key_size]
        self.round_keys = self._key_expansion()

    def _sub_bytes(self, state: List[List[int]]) -> List[List[int]]:
        """SubBytes transformation"""
        return [[self.S_BOX[val] for val in row] for row in state]

    def _inv_sub_bytes(self, state: List[List[int]]) -> List[List[int]]:
        """Inverse SubBytes transformation"""
        return [[self.INV_S_BOX[val] for val in row] for row in state]

    def _shift_rows(self, state: List[List[int]]) -> List[List[int]]:
        """ShiftRows transformation"""
        return [row[i:] + row[:i] for i, row in enumerate(state)]

    def _inv_shift_rows(self, state: List[List[int]]) -> List[List[int]]:
        """Inverse ShiftRows transformation"""
        return [row[-i:] + row[:-i] if i else row[:]
                for i, row in enumerate(state)]

    def _mix_columns(self, state: List[List[int]]) -> List[List[int]]:
        """MixColumns transformation"""
        mixed = [[0] * 4 for _ in range(4)]
        for col in range(4):
            a = [state[row][col] for row in range(4)]
            mixed[0][col] = self._gf_mult(a[0], 2) ^ self._gf_mult(a[1], 3) ^ a[2] ^ a[3]
            mixed[1][col] = a[0] ^ self._gf_mult(a[1], 2) ^ self._gf_mult(a[2], 3) ^ a[3]
            mixed[2][col] = a[0] ^ a[1] ^ self._gf_mult(a[2], 2) ^ self._gf_mult(a[3], 3)
            mixed[3][col] = self._gf_mult(a[0], 3) ^ a[1] ^ a[2] ^ self._gf_mult(a[3], 2)
        return mixed

    def _inv_mix_columns(self, state: List[List[int]]) -> List[List[int]]:
        """Inverse MixColumns transformation"""
        mixed = [[0] * 4 for _ in range(4)]
        for col in range(4):
            a = [state[row][col] for row in range(4)]
            mixed[0][col] = (self._gf_mult(a[0], 0x0e) ^ self._gf_mult(a[1], 0x0b) ^
                             self._gf_mult(a[2], 0x0d) ^ self._gf_mult(a[3], 0x09))
            mixed[1][col] = (self._gf_mult(a[0], 0x09) ^ self._gf_mult(a[1], 0x0e) ^
                             self._gf_mult(a[2], 0x0b) ^ self._gf_mult(a[3], 0x0d))
            mixed[2][col] = (self._gf_mult(a[0], 0x0d) ^ self._gf_mult(a[1], 0x09) ^
                             self._gf_mult(a[2], 0x0e) ^ self._gf_mult(a[3], 0x0b))
            mixed[3][col] = (self._gf_mult(a[0], 0x0b) ^ self._gf_mult(a[1], 0x0d) ^
                             self._gf_mult(a[2], 0x09) ^ self._gf_mult(a[3], 0x0e))
        return mixed

    def _gf_mult(self, a: int, b: int) -> int:
        """Galois Field multiplication"""
        result = 0
        for _ in range(8):
            if b & 1:
                result ^= a
            a <<= 1
            if a & 0x100:
                a ^= 0x11b
            b >>= 1
        return result & 0xff

    def _add_round_key(self, state: List[List[int]], round_key: List[List[int]]) -> List[List[int]]:
        """AddRoundKey transformation"""
        return [[state[i][j] ^ round_key[j][i] for j in range(4)] for i in range(4)]

    def _key_expansion(self) -> List[List[List[int]]]:
        """Key expansion to generate round keys"""
        key_words = []

        # Convert key to 4-byte words
        for i in range(0, len(self.key), 4):
            key_words.append(list(self.key[i:i + 4]))

        key_size_words = len(key_words)
        total_words = 4 * (self.rounds + 1)

        for i in range(key_size_words, total_words):
            temp = key_words[i - 1][:]

            if i % key_size_words == 0:
                # RotWord
                temp = temp[1:] + temp[:1]
                # SubWord
                temp = [self.S_BOX[val] for val in temp]
                # XOR with Rcon
                temp[0] ^= self.R_CON[(i // key_size_words) - 1]
            elif key_size_words > 6 and i % key_size_words == 4:
                # SubWord for AES-256
                temp = [self.S_BOX[val] for val in temp]

            # XOR with previous word
            key_words.append([key_words[i - key_size_words][j] ^ temp[j]
                              for j in range(4)])

        # Group words into round keys (each round key is 4 words)
        return [[key_words[i + j] for j in range(4)]
                for i in range(0, total_words, 4)]

    def _encrypt_block(self, plaintext: bytes) -> bytes:
        """Encrypt a single 16-byte block"""
        if len(plaintext) != BLOCK_SIZE:
            raise ValueError("Block must be 16 bytes")

        # Column-major state matrix: state[row][col] = input[row + 4 * col]
        state = [[plaintext[row + 4 * col] for col in range(4)] for row in range(4)]

        state = self._add_round_key(state, self.round_keys[0])

        for round_num in range(1, self.rounds):
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, self.round_keys[round_num])

        # Final round (no MixColumns)
        state = self._sub_bytes(state)
        state = self._shift_rows(state)
        state = self._add_round_key(state, self.round_keys[self.rounds])

        return bytes(state[row][col] for col in range(4) for row in range(4))

    def _decrypt_block(self, ciphertext: bytes) -> bytes:
        """Decrypt a single 16-byte block"""
        if len(ciphertext) != BLOCK_SIZE:
            raise ValueError("Block must be 16 bytes")

        state = [[ciphertext[row + 4 * col] for col in range(4)] for row in range(4)]

        state = self._add_round_key(state, self.round_keys[self.rounds])

        for round_num in range(self.rounds - 1, 0, -1):
            state = self._inv_shift_rows(state)
            state = self._inv_sub_bytes(state)
            state = self._add_round_key(state, self.round_keys[round_num])
            state = self._inv_mix_columns(state)

        state = self._inv_shift_rows(state)
        state = self._inv_sub_bytes(state)
        state = self._add_round_key(state, self.round_keys[0])

        return bytes(state[row][col] for col in range(4) for row in range(4))

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

    def _check_iv(self, iv: Optional[bytes]) -> None:
        """Validate the IV for the configured mode"""
        if self.mode == AESMode.ECB:
            return
        if iv is None:
            raise ValueError("IV required for this mode")
        if len(iv) != BLOCK_SIZE:
            raise ValueError("IV must be 16 bytes")

    def encrypt(self, plaintext: bytes, iv: bytes = None) -> bytes:
        """
        Encrypt data

        Args:
            plaintext: Data to encrypt
            iv: Initialization vector (required for CBC, CFB, OFB, CTR)

        Returns:
            Encrypted data (the IV is not prepended; keep it alongside)
        """
        self._check_iv(iv)

        if self.mode in BLOCK_MODES:
            plaintext = self._pad(plaintext)

        if self.mode == AESMode.ECB:
            return self._encrypt_ecb(plaintext)
        if self.mode == AESMode.CBC:
            return self._encrypt_cbc(plaintext, iv)
        if self.mode == AESMode.CFB:
            return self._encrypt_cfb(plaintext, iv)
        if self.mode == AESMode.OFB:
            return self._keystream_xor(plaintext, iv)
        if self.mode == AESMode.CTR:
            return self._crypt_ctr(plaintext, iv)
        raise ValueError(f"Unsupported mode: {self.mode}")

    def decrypt(self, ciphertext: bytes, iv: bytes = None) -> bytes:
        """
        Decrypt data

        Args:
            ciphertext: Data to decrypt
            iv: Initialization vector (required for CBC, CFB, OFB, CTR)

        Returns:
            Decrypted data
        """
        self._check_iv(iv)

        if self.mode == AESMode.ECB:
            plaintext = self._decrypt_ecb(ciphertext)
        elif self.mode == AESMode.CBC:
            plaintext = self._decrypt_cbc(ciphertext, iv)
        elif self.mode == AESMode.CFB:
            plaintext = self._decrypt_cfb(ciphertext, iv)
        elif self.mode == AESMode.OFB:
            plaintext = self._keystream_xor(ciphertext, iv)
        elif self.mode == AESMode.CTR:
            plaintext = self._crypt_ctr(ciphertext, iv)
        else:
            raise ValueError(f"Unsupported mode: {self.mode}")

        if self.mode in BLOCK_MODES:
            plaintext = self._unpad(plaintext)
        return plaintext

    def _encrypt_ecb(self, plaintext: bytes) -> bytes:
        """ECB mode encryption"""
        return b''.join(self._encrypt_block(plaintext[i:i + BLOCK_SIZE])
                        for i in range(0, len(plaintext), BLOCK_SIZE))

    def _decrypt_ecb(self, ciphertext: bytes) -> bytes:
        """ECB mode decryption"""
        return b''.join(self._decrypt_block(ciphertext[i:i + BLOCK_SIZE])
                        for i in range(0, len(ciphertext), BLOCK_SIZE))

    def _encrypt_cbc(self, plaintext: bytes, iv: bytes) -> bytes:
        """CBC mode encryption"""
        ciphertext = b''
        prev_block = iv

        for i in range(0, len(plaintext), BLOCK_SIZE):
            block = plaintext[i:i + BLOCK_SIZE]
            block = bytes(block[j] ^ prev_block[j] for j in range(BLOCK_SIZE))
            prev_block = self._encrypt_block(block)
            ciphertext += prev_block

        return ciphertext

    def _decrypt_cbc(self, ciphertext: bytes, iv: bytes) -> bytes:
        """CBC mode decryption"""
        if len(ciphertext) % BLOCK_SIZE != 0:
            raise ValueError("Ciphertext length must be a multiple of 16 bytes")

        plaintext = b''
        prev_block = iv

        for i in range(0, len(ciphertext), BLOCK_SIZE):
            block = ciphertext[i:i + BLOCK_SIZE]
            decrypted = self._decrypt_block(block)
            plaintext += bytes(decrypted[j] ^ prev_block[j] for j in range(BLOCK_SIZE))
            prev_block = block

        return plaintext

    def _encrypt_cfb(self, plaintext: bytes, iv: bytes) -> bytes:
        """CFB mode encryption (full-block feedback)"""
        ciphertext = b''
        feedback = iv

        for i in range(0, len(plaintext), BLOCK_SIZE):
            block = plaintext[i:i + BLOCK_SIZE]
            keystream = self._encrypt_block(feedback)
            encrypted = bytes(block[j] ^ keystream[j] for j in range(len(block)))
            ciphertext += encrypted
            feedback = encrypted.ljust(BLOCK_SIZE, b'\x00')

        return ciphertext

    def _decrypt_cfb(self, ciphertext: bytes, iv: bytes) -> bytes:
        """CFB mode decryption (full-block feedback)"""
        plaintext = b''
        feedback = iv

        for i in range(0, len(ciphertext), BLOCK_SIZE):
            block = ciphertext[i:i + BLOCK_SIZE]
            keystream = self._encrypt_block(feedback)
            plaintext += bytes(block[j] ^ keystream[j] for j in range(len(block)))
            feedback = block.ljust(BLOCK_SIZE, b'\x00')

        return plaintext

    def _keystream_xor(self, data: bytes, iv: bytes) -> bytes:
        """OFB mode: XOR data with the cipher output feedback keystream"""
        result = b''
        state = iv

        for i in range(0, len(data), BLOCK_SIZE):
            block = data[i:i + BLOCK_SIZE]
            state = self._encrypt_block(state)
            result += bytes(block[j] ^ state[j] for j in range(len(block)))

        return result

    def _crypt_ctr(self, data: bytes, nonce: bytes) -> bytes:
        """CTR mode encryption/decryption"""
        result = b''
        high, low = struct.unpack('>QQ', nonce)

        for i in range(0, len(data), BLOCK_SIZE):
            block = data[i:i + BLOCK_SIZE]
            keystream = self._encrypt_block(struct.pack('>QQ', high, low))
            result += bytes(block[j] ^ keystream[j] for j in range(len(block)))
            low = (low + 1) & 0xFFFFFFFFFFFFFFFF
            if low == 0:
                high = (high + 1) & 0xFFFFFFFFFFFFFFFF

        return result

    @staticmethod
    def generate_iv() -> bytes:
        """Generate a random 16-byte IV using the OS CSPRNG"""
        return os.urandom(BLOCK_SIZE)
