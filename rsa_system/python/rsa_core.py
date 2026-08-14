#!/usr/bin/env python3
"""
RSA Cryptography System Implementation
Complete RSA with key generation, encryption, decryption, signatures
"""

import os
import random
import hashlib
from typing import Tuple, Optional
from enum import Enum


def _nonzero_random_bytes(length: int) -> bytes:
    """
    Generate random bytes that contain no zero byte (PKCS#1 v1.5 filler)
    
    Args:
        length: Number of bytes to generate
    
    Returns:
        Random non-zero bytes
    """
    if length < 0:
        raise ValueError("Length must be non-negative")
    
    filler = bytearray()
    while len(filler) < length:
        filler.extend(b for b in os.urandom(length - len(filler)) if b != 0)
    return bytes(filler)


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
    
    def _require_keypair(self) -> None:
        """
        Ensure a key pair has been generated
        
        Raises:
            ValueError: if generate_keypair() has not been called yet
        """
        if self.n == 0 or self.d == 0:
            raise ValueError("No RSA key pair available; call generate_keypair() first")
    
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
    
    def encrypt(self, plaintext: int, public_key: Optional[Tuple[int, int]] = None) -> int:
        """
        Encrypt using RSA
        
        Args:
            plaintext: Plaintext as integer
            public_key: (n, e) tuple, uses self.n, self.e if None
        
        Returns:
            Ciphertext as integer
        """
        if public_key is None:
            self._require_keypair()
            n, e = self.n, self.e
        else:
            n, e = public_key
        
        if plaintext < 0:
            raise ValueError("Plaintext must be non-negative")
        
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
        if private_key is None:
            self._require_keypair()
            n, d, p, q, dP, dQ, qInv = self.n, self.d, self.p, self.q, self.dP, self.dQ, self.qInv
        else:
            n, d, p, q, dP, dQ, qInv = private_key
        
        if ciphertext < 0:
            raise ValueError("Ciphertext must be non-negative")
        
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
        hash_obj = hashlib.sha256(message.encode())
        message_hash = int.from_bytes(hash_obj.digest(), byteorder='big')
        
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
        # Hash the message
        if hash_algorithm == "SHA-256":
            hash_obj = hashlib.sha256(message.encode())
        elif hash_algorithm == "SHA-512":
            hash_obj = hashlib.sha512(message.encode())
        else:
            raise ValueError("Unsupported hash algorithm")
        
        message_hash = int.from_bytes(hash_obj.digest(), byteorder='big')
        
        # Decrypt signature
        decrypted_hash = self.encrypt(signature, public_key)
        
        return decrypted_hash == message_hash
    
    def encrypt_bytes(self, data: bytes, public_key: Optional[Tuple[int, int]] = None) -> bytes:
        """
        Encrypt bytes using RSA with PKCS#1 v1.5 padding
        
        Args:
            data: Data to encrypt
            public_key: Public key tuple
        
        Returns:
            Encrypted data
        """
        if public_key is None:
            self._require_keypair()
            n, e = self.n, self.e
        else:
            n, e = public_key
        
        # Calculate maximum block size
        k = (n.bit_length() + 7) // 8
        max_block_size = k - 11  # PKCS#1 v1.5 padding overhead
        
        if max_block_size <= 0:
            raise ValueError(
                f"Modulus is too small for PKCS#1 v1.5 padding ({k} bytes, needs > 11)"
            )
        
        encrypted_data = b''
        
        for i in range(0, len(data), max_block_size):
            block = data[i:i+max_block_size]
            
            # PKCS#1 v1.5 padding: filler bytes must all be non-zero so that the
            # 0x00 separator stays unambiguous
            padding = b'\x00\x02'
            padding += _nonzero_random_bytes(k - len(block) - 3)
            padding += b'\x00'
            padded_block = padding + block
            
            # Convert to integer and encrypt
            m = int.from_bytes(padded_block, byteorder='big')
            c = self.encrypt(m, public_key)
            
            # Convert back to bytes
            encrypted_block = c.to_bytes(k, byteorder='big')
            encrypted_data += encrypted_block
        
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
        if private_key is None:
            self._require_keypair()
            n = self.n
        else:
            n = private_key[0]
        
        # Calculate block size
        k = (n.bit_length() + 7) // 8
        
        if len(data) % k != 0:
            raise ValueError(
                f"Ciphertext length ({len(data)} bytes) is not a multiple of the "
                f"modulus size ({k} bytes)"
            )
        
        decrypted_data = b''
        
        for i in range(0, len(data), k):
            block = data[i:i+k]
            
            # Convert to integer and decrypt
            c = int.from_bytes(block, byteorder='big')
            m = self.decrypt(c, private_key)
            
            # Convert back to bytes
            padded_block = m.to_bytes(k, byteorder='big')
            
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
        if public_key is None:
            self._require_keypair()
            n, e = self.n, self.e
        else:
            n, e = public_key
        
        # Simple PEM format (not full X.509)
        n_bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
        e_bytes = e.to_bytes((e.bit_length() + 7) // 8, byteorder='big')
        
        pem = "-----BEGIN RSA PUBLIC KEY-----\n"
        pem += f"Modulus: {n_bytes.hex()}\n"
        pem += f"Exponent: {e_bytes.hex()}\n"
        pem += "-----END RSA PUBLIC KEY-----\n"
        
        return pem
    
    def export_private_key(self) -> str:
        """
        Export private key in PEM format
        
        Returns:
            PEM formatted private key
        """
        self._require_keypair()
        
        n_bytes = self.n.to_bytes((self.n.bit_length() + 7) // 8, byteorder='big')
        d_bytes = self.d.to_bytes((self.d.bit_length() + 7) // 8, byteorder='big')
        p_bytes = self.p.to_bytes((self.p.bit_length() + 7) // 8, byteorder='big')
        q_bytes = self.q.to_bytes((self.q.bit_length() + 7) // 8, byteorder='big')
        
        pem = "-----BEGIN RSA PRIVATE KEY-----\n"
        pem += f"Modulus: {n_bytes.hex()}\n"
        pem += f"Private Exponent: {d_bytes.hex()}\n"
        pem += f"Prime p: {p_bytes.hex()}\n"
        pem += f"Prime q: {q_bytes.hex()}\n"
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
        import time
        
        times = []
        for _ in range(iterations):
            rsa = RSA(key_size)
            start_time = time.time()
            rsa.generate_keypair()
            end_time = time.time()
            times.append(end_time - start_time)
        
        return {
            'key_size': key_size,
            'iterations': iterations,
            'average_time': sum(times) / len(times),
            'min_time': min(times),
            'max_time': max(times),
            'total_time': sum(times)
        }
    
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
        import time
        
        message = os.urandom(message_size)
        public_key, _ = rsa.generate_keypair()
        
        times = []
        for _ in range(iterations):
            start_time = time.time()
            rsa.encrypt_bytes(message, public_key)
            end_time = time.time()
            times.append(end_time - start_time)
        
        return {
            'message_size': message_size,
            'iterations': iterations,
            'average_time': sum(times) / len(times),
            'min_time': min(times),
            'max_time': max(times),
            'total_time': sum(times)
        }
    
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
        import time
        
        message = os.urandom(message_size)
        public_key, private_key = rsa.generate_keypair()
        encrypted = rsa.encrypt_bytes(message, public_key)
        
        times = []
        for _ in range(iterations):
            start_time = time.time()
            rsa.decrypt_bytes(encrypted, private_key)
            end_time = time.time()
            times.append(end_time - start_time)
        
        return {
            'message_size': message_size,
            'iterations': iterations,
            'average_time': sum(times) / len(times),
            'min_time': min(times),
            'max_time': max(times),
            'total_time': sum(times)
        }