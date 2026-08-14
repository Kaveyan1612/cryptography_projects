#!/usr/bin/env python3
"""
RSA Cryptography System Implementation
Complete RSA with key generation, encryption, decryption, signatures
"""

import hashlib
import os
import random
import sys
from enum import Enum
from pathlib import Path
from typing import Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from common.pathsetup import add_project_paths

add_project_paths()

from common import benchmark
from common.intutil import byte_length, bytes_to_int, int_to_bytes


class RSAKeySize(Enum):
    """RSA key sizes"""
    RSA_1024 = 1024
    RSA_2048 = 2048
    RSA_3072 = 3072
    RSA_4096 = 4096


class RSAPadding(Enum):
    """RSA padding schemes"""
    PKCS1_v1_5 = 0
    OAEP = 1
    PSS = 2


class RSA:
    """RSA encryption/decryption implementation"""
    
    def __init__(self, key_size: int = 2048):
        """
        Initialize RSA with specified key size
        
        Args:
            key_size: Key size in bits (1024, 2048, 3072, 4096)
        """
        if key_size not in [1024, 2048, 3072, 4096]:
            raise ValueError("Key size must be 1024, 2048, 3072, or 4096 bits")
        
        self.key_size = key_size
        self.n = 0      # Modulus
        self.e = 65537  # Public exponent (standard)
        self.d = 0      # Private exponent
        self.p = 0      # Prime p
        self.q = 0      # Prime q
        self.dP = 0     # d mod (p-1)
        self.dQ = 0     # d mod (q-1)
        self.qInv = 0    # q^(-1) mod p
    
    def generate_keypair(self) -> Tuple[Tuple[int, int], Tuple[int, int, int, int, int]]:
        """
        Generate RSA key pair
        
        Returns:
            Tuple of (public_key, private_key)
            public_key: (n, e)
            private_key: (n, d, p, q, dP, dQ, qInv)
        """
        # Generate two large primes
        self.p = self._generate_large_prime(self.key_size // 2)
        self.q = self._generate_large_prime(self.key_size // 2)
        
        # Ensure p != q
        while self.p == self.q:
            self.q = self._generate_large_prime(self.key_size // 2)
        
        # Calculate modulus
        self.n = self.p * self.q
        
        # Calculate Euler's totient function
        phi = (self.p - 1) * (self.q - 1)
        
        # Calculate private exponent
        self.d = self._mod_inverse(self.e, phi)
        
        # Calculate CRT parameters for faster decryption
        self.dP = self.d % (self.p - 1)
        self.dQ = self.d % (self.q - 1)
        self.qInv = self._mod_inverse(self.q, self.p)
        
        public_key = (self.n, self.e)
        private_key = (self.n, self.d, self.p, self.q, self.dP, self.dQ, self.qInv)
        
        return public_key, private_key
    
    def _generate_large_prime(self, bit_length: int) -> int:
        """
        Generate a large prime number using Miller-Rabin test
        
        Args:
            bit_length: Desired bit length of the prime
        
        Returns:
            Large prime number
        """
        while True:
            # Generate random odd number
            candidate = random.getrandbits(bit_length)
            candidate |= (1 << bit_length - 1) | 1  # Ensure odd and correct bit length
            
            # Test for primality
            if self._is_prime(candidate):
                return candidate
    
    def _is_prime(self, n: int, k: int = 40) -> bool:
        """
        Miller-Rabin primality test
        
        Args:
            n: Number to test
            k: Number of test rounds
        
        Returns:
            True if n is probably prime, False if definitely composite
        """
        if n < 2:
            return False
        if n == 2:
            return True
        if n % 2 == 0:
            return False
        
        # Handle small numbers
        if n < 10:
            return n in [2, 3, 5, 7]
        
        # Write n-1 as 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        # Test k times
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
            
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        
        return True
    
    def _mod_inverse(self, a: int, m: int) -> int:
        """
        Calculate modular inverse using extended Euclidean algorithm
        
        Args:
            a: Number to find inverse of
            m: Modulus
        
        Returns:
            Modular inverse of a mod m
        """
        def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        gcd, x, _ = extended_gcd(a, m)
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        return x % m
    
    def _public_key(self, public_key: Optional[Tuple[int, int]]) -> Tuple[int, int]:
        """Return the given public key or this instance's key material"""
        if public_key is None:
            return self.n, self.e
        return public_key
    
    def _private_key(self, private_key: Optional[Tuple[int, ...]]) -> Tuple[int, ...]:
        """Return the given private key or this instance's key material"""
        if private_key is None:
            return (self.n, self.d, self.p, self.q, self.dP, self.dQ, self.qInv)
        return private_key
    
    def encrypt(self, plaintext: int, public_key: Optional[Tuple[int, int]] = None) -> int:
        """
        Encrypt using RSA
        
        Args:
            plaintext: Plaintext as integer
            public_key: (n, e) tuple, uses self.n, self.e if None
        
        Returns:
            Ciphertext as integer
        """
        n, e = self._public_key(public_key)
        
        if plaintext >= n:
            raise ValueError("Plaintext must be less than modulus")
        
        return pow(plaintext, e, n)
    
    def decrypt(self, ciphertext: int, private_key: Optional[Tuple[int, int, int, int, int, int, int]] = None) -> int:
        """
        Decrypt using RSA with CRT optimization
        
        Args:
            ciphertext: Ciphertext as integer
            private_key: (n, d, p, q, dP, dQ, qInv) tuple
        
        Returns:
            Plaintext as integer
        """
        n, d, p, q, dP, dQ, qInv = self._private_key(private_key)
        
        if ciphertext >= n:
            raise ValueError("Ciphertext must be less than modulus")
        
        # CRT optimization for faster decryption
        m1 = pow(ciphertext, dP, p)
        m2 = pow(ciphertext, dQ, q)
        
        h = (qInv * (m1 - m2)) % p
        m = m2 + h * q
        
        return m % n
    
    def sign(self, message: str, private_key: Optional[Tuple[int, int, int, int, int, int, int]] = None) -> Tuple[int, str]:
        """
        Create digital signature
        
        Args:
            message: Message to sign
            private_key: Private key tuple
        
        Returns:
            Tuple of (signature, hash_algorithm)
        """
        # Hash the message
        hash_algorithm = "SHA-256"
        message_hash = self._message_hash(message, hash_algorithm)
        
        # Sign the hash
        signature = self.decrypt(message_hash, private_key)
        
        return signature, hash_algorithm
    
    def verify(self, message: str, signature: int, public_key: Optional[Tuple[int, int]] = None, 
              hash_algorithm: str = "SHA-256") -> bool:
        """
        Verify digital signature
        
        Args:
            message: Original message
            signature: Signature to verify
            public_key: Public key tuple
            hash_algorithm: Hash algorithm used
        
        Returns:
            True if signature is valid, False otherwise
        """
        message_hash = self._message_hash(message, hash_algorithm)
        
        # Decrypt signature
        decrypted_hash = self.encrypt(signature, public_key)
        
        return decrypted_hash == message_hash
    
    @staticmethod
    def _message_hash(message: str, hash_algorithm: str) -> int:
        """Hash a message with the named algorithm and return it as an integer"""
        if hash_algorithm == "SHA-256":
            hash_obj = hashlib.sha256(message.encode())
        elif hash_algorithm == "SHA-512":
            hash_obj = hashlib.sha512(message.encode())
        else:
            raise ValueError("Unsupported hash algorithm")
        
        return bytes_to_int(hash_obj.digest())
    
    def encrypt_bytes(self, data: bytes, public_key: Optional[Tuple[int, int]] = None) -> bytes:
        """
        Encrypt bytes using RSA with PKCS#1 v1.5 padding
        
        Args:
            data: Data to encrypt
            public_key: Public key tuple
        
        Returns:
            Encrypted data
        """
        n, e = self._public_key(public_key)
        
        # Calculate maximum block size
        k = byte_length(n)
        max_block_size = k - 11  # PKCS#1 v1.5 padding overhead
        
        encrypted_data = b''
        
        for i in range(0, len(data), max_block_size):
            block = data[i:i+max_block_size]
            
            # PKCS#1 v1.5 padding
            padding = b'\x00\x02'
            padding += os.urandom(k - len(block) - 3)
            padding += b'\x00'
            padded_block = padding + block
            
            # Convert to integer and encrypt
            c = self.encrypt(bytes_to_int(padded_block), public_key)
            
            # Convert back to bytes
            encrypted_data += int_to_bytes(c, k)
        
        return encrypted_data
    
    def decrypt_bytes(self, data: bytes, private_key: Optional[Tuple[int, int, int, int, int, int, int]] = None) -> bytes:
        """
        Decrypt bytes using RSA with PKCS#1 v1.5 padding
        
        Args:
            data: Data to decrypt
            private_key: Private key tuple
        
        Returns:
            Decrypted data
        """
        n = self._private_key(private_key)[0]
        
        # Calculate block size
        k = byte_length(n)
        
        decrypted_data = b''
        
        for i in range(0, len(data), k):
            block = data[i:i+k]
            
            # Convert to integer and decrypt
            m = self.decrypt(bytes_to_int(block), private_key)
            
            # Convert back to bytes
            padded_block = int_to_bytes(m, k)
            
            # Remove PKCS#1 v1.5 padding
            if padded_block[0] != 0x00 or padded_block[1] != 0x02:
                raise ValueError("Invalid PKCS#1 v1.5 padding")
            
            # Find separator
            separator_index = padded_block.find(b'\x00', 2)
            if separator_index == -1:
                raise ValueError("Invalid PKCS#1 v1.5 padding")
            
            decrypted_block = padded_block[separator_index + 1:]
            decrypted_data += decrypted_block
        
        return decrypted_data
    
    def key_exchange(self, other_public_key: Tuple[int, int]) -> Tuple[int, int]:
        """
        Perform key exchange (Diffie-Hellman style with RSA)
        
        Args:
            other_public_key: Other party's public key
        
        Returns:
            Shared secret
        """
        # Generate random session key
        session_key = random.getrandbits(256)
        
        # Encrypt session key with other party's public key
        encrypted_key = self.encrypt(session_key, other_public_key)
        
        return encrypted_key, session_key
    
    def export_public_key(self, public_key: Optional[Tuple[int, int]] = None) -> str:
        """
        Export public key in PEM format
        
        Args:
            public_key: Public key tuple
        
        Returns:
            PEM formatted public key
        """
        n, e = self._public_key(public_key)
        
        # Simple PEM format (not full X.509)
        pem = "-----BEGIN RSA PUBLIC KEY-----\n"
        pem += f"Modulus: {self._hex(n)}\n"
        pem += f"Exponent: {self._hex(e)}\n"
        pem += "-----END RSA PUBLIC KEY-----\n"
        
        return pem
    
    @staticmethod
    def _hex(value: int) -> str:
        """Render an integer as big-endian hex for the PEM-style exports"""
        return int_to_bytes(value).hex()
    
    def export_private_key(self) -> str:
        """
        Export private key in PEM format
        
        Returns:
            PEM formatted private key
        """
        pem = "-----BEGIN RSA PRIVATE KEY-----\n"
        pem += f"Modulus: {self._hex(self.n)}\n"
        pem += f"Private Exponent: {self._hex(self.d)}\n"
        pem += f"Prime p: {self._hex(self.p)}\n"
        pem += f"Prime q: {self._hex(self.q)}\n"
        pem += "-----END RSA PRIVATE KEY-----\n"
        
        return pem
    
    def get_key_info(self) -> dict:
        """
        Get information about the current key pair
        
        Returns:
            Dictionary with key information
        """
        return {
            'key_size': self.key_size,
            'modulus_bits': self.n.bit_length(),
            'public_exponent': self.e,
            'private_exponent_bits': self.d.bit_length(),
            'prime_p_bits': self.p.bit_length(),
            'prime_q_bits': self.q.bit_length()
        }


class RSABenchmark:
    """Benchmarking utilities for RSA operations"""
    
    @staticmethod
    def benchmark_key_generation(key_size: int, iterations: int = 10) -> dict:
        """
        Benchmark RSA key generation
        
        Args:
            key_size: Key size in bits
            iterations: Number of iterations
        
        Returns:
            Benchmark results
        """
        results = benchmark.time_operation(
            lambda: RSA(key_size).generate_keypair(), iterations)
        
        return {'key_size': key_size, **results}
    
    @staticmethod
    def benchmark_encryption(rsa: RSA, message_size: int, iterations: int = 100) -> dict:
        """
        Benchmark RSA encryption
        
        Args:
            rsa: RSA instance with generated keys
            message_size: Size of message in bytes
            iterations: Number of iterations
        
        Returns:
            Benchmark results
        """
        message = os.urandom(message_size)
        public_key, _ = rsa.generate_keypair()
        
        results = benchmark.time_operation(
            lambda: rsa.encrypt_bytes(message, public_key), iterations)
        
        return {'message_size': message_size, **results}
    
    @staticmethod
    def benchmark_decryption(rsa: RSA, message_size: int, iterations: int = 100) -> dict:
        """
        Benchmark RSA decryption
        
        Args:
            rsa: RSA instance with generated keys
            message_size: Size of message in bytes
            iterations: Number of iterations
        
        Returns:
            Benchmark results
        """
        message = os.urandom(message_size)
        public_key, private_key = rsa.generate_keypair()
        encrypted = rsa.encrypt_bytes(message, public_key)
        
        results = benchmark.time_operation(
            lambda: rsa.decrypt_bytes(encrypted, private_key), iterations)
        
        return {'message_size': message_size, **results}