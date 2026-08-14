# AES Decryption Modes - Comprehensive Documentation

## Overview

This document provides detailed information about the AES decryption modes implemented in the cryptography system, including their mathematical foundations, security properties, and practical usage.

## Table of Contents

1. [Introduction](#introduction)
2. [AES Modes Overview](#aes-modes-overview)
3. [Mode-Specific Decryption](#mode-specific-decryption)
4. [Security Analysis](#security-analysis)
5. [Performance Characteristics](#performance-characteristics)
6. [Usage Examples](#usage-examples)
7. [Best Practices](#best-practices)

## Introduction

The Advanced Encryption Standard (AES) supports multiple operation modes, each with different characteristics for encryption and decryption. This implementation provides support for all five standard AES modes:

- **ECB** (Electronic Codebook)
- **CBC** (Cipher Block Chaining)
- **CFB** (Cipher Feedback)
- **OFB** (Output Feedback)
- **CTR** (Counter)

## AES Modes Overview

### Electronic Codebook (ECB)

**Description:** The simplest mode where each 128-bit block is encrypted independently.

**Encryption:** `C_i = E_K(P_i)`  
**Decryption:** `P_i = D_K(C_i)`

**Characteristics:**
- ✅ Simple and fast
- ✅ Parallelizable
- ❌ Same plaintext produces same ciphertext
- ❌ No error propagation
- ❌ Vulnerable to pattern analysis

**IV Requirement:** None

### Cipher Block Chaining (CBC)

**Description:** Each plaintext block is XORed with the previous ciphertext block before encryption.

**Encryption:** `C_i = E_K(P_i ⊕ C_{i-1})` (with `C_0 = IV`)  
**Decryption:** `P_i = D_K(C_i) ⊕ C_{i-1}` (with `C_0 = IV`)

**Characteristics:**
- ✅ Hides patterns in plaintext
- ✅ Random IV ensures same plaintext produces different ciphertext
- ✅ Widely used and standardized
- ❌ Sequential processing (not parallelizable)
- ❌ Error propagation (1-bit error affects current and next block)
- ❌ Padding oracle attacks possible

**IV Requirement:** Required (16 bytes, should be random and unique)

### Cipher Feedback (CFB)

**Description:** Transforms block cipher into a self-synchronizing stream cipher.

**Encryption:** `C_i = P_i ⊕ E_K(C_{i-1})` (with `C_0 = IV`)  
**Decryption:** `P_i = C_i ⊕ E_K(C_{i-1})` (with `C_0 = IV`)

**Characteristics:**
- ✅ Can handle partial blocks
- ✅ Self-synchronizing (recovers from bit errors)
- ✅ No padding required
- ❌ Sequential processing
- ❌ Error propagation (1-bit error affects next few blocks)
- ❌ Less common than CBC

**IV Requirement:** Required (16 bytes, should be random and unique)

### Output Feedback (OFB)

**Description:** Transforms block cipher into a synchronous stream cipher.

**Encryption:** `C_i = P_i ⊕ O_i` where `O_i = E_K(O_{i-1})` (with `O_0 = IV`)  
**Decryption:** `P_i = C_i ⊕ O_i` where `O_i = E_K(O_{i-1})` (with `O_0 = IV`)

**Characteristics:**
- ✅ No error propagation (bit errors don't spread)
- ✅ Can pre-generate keystream
- ✅ No padding required
- ❌ Sequential processing
- ❌ IV must never be reused
- ❌ Vulnerable to bit-flipping attacks

**IV Requirement:** Required (16 bytes, must be unique - never reuse!)

### Counter (CTR)

**Description:** Transforms block cipher into a stream cipher using a counter.

**Encryption:** `C_i = P_i ⊕ E_K(Nonce || Counter_i)`  
**Decryption:** `P_i = C_i ⊕ E_K(Nonce || Counter_i)`

**Characteristics:**
- ✅ Fully parallelizable
- ✅ Random access to ciphertext
- ✅ No error propagation
- ✅ No padding required
- ✅ Can encrypt/decrypt in parallel
- ❌ Counter must never be reused
- ❌ Requires unique nonce for each message

**IV Requirement:** Required (nonce + counter, must be unique)

## Mode-Specific Decryption

### ECB Decryption Implementation

```python
def _decrypt_ecb(self, ciphertext: bytes) -> bytes:
    """ECB mode decryption - each block decrypted independently"""
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    plaintext = bytearray()
    
    for block in blocks:
        # Pad if necessary
        if len(block) < 16:
            block = block + b'\x00' * (16 - len(block))
        # Decrypt block independently
        decrypted = self._xor_encrypt(block, self.key)
        plaintext.extend(decrypted)
    
    return bytes(plaintext)
```

**Key Points:**
- Each block decrypted independently
- No IV required
- Same ciphertext always decrypts to same plaintext
- Vulnerable to pattern analysis

### CBC Decryption Implementation

```python
def _decrypt_cbc(self, ciphertext: bytes, iv: bytes) -> bytes:
    """CBC mode decryption - chain cipher blocks with previous ciphertext"""
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    plaintext = bytearray()
    prev_block = iv
    
    for block in blocks:
        # Decrypt block
        decrypted = self._xor_encrypt(block, self.key)
        # XOR with previous ciphertext block
        xor_result = self._xor_blocks(decrypted, prev_block)
        plaintext.extend(xor_result)
        prev_block = block
    
    return bytes(plaintext)
```

**Key Points:**
- Requires IV (initialization vector)
- Chaining using previous ciphertext block
- First block uses IV
- Error propagation to next block

### CFB Decryption Implementation

```python
def _decrypt_cfb(self, ciphertext: bytes, iv: bytes) -> bytes:
    """CFB mode decryption - cipher feedback mode"""
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    plaintext = bytearray()
    feedback = iv
    
    for block in blocks:
        # Encrypt feedback register
        encrypted_feedback = self._xor_encrypt(feedback, self.key)
        # XOR with ciphertext to get plaintext
        decrypted = self._xor_blocks(block, encrypted_feedback)
        plaintext.extend(decrypted)
        feedback = block  # Feedback is ciphertext
    
    return bytes(plaintext)
```

**Key Points:**
- Self-synchronizing stream cipher
- Feedback register updated with ciphertext
- Can handle partial blocks
- Error propagation limited to few blocks

### OFB Decryption Implementation

```python
def _decrypt_ofb(self, ciphertext: bytes, iv: bytes) -> bytes:
    """OFB mode decryption - output feedback mode"""
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    plaintext = bytearray()
    feedback = iv
    
    for block in blocks:
        # Encrypt feedback register
        encrypted_feedback = self._xor_encrypt(feedback, self.key)
        # XOR with ciphertext to get plaintext
        decrypted = self._xor_blocks(block, encrypted_feedback)
        plaintext.extend(decrypted)
        feedback = encrypted_feedback  # Feedback is encrypted output
    
    return bytes(plaintext)
```

**Key Points:**
- Synchronous stream cipher
- Feedback register updated with encrypted output
- No error propagation
- IV must never be reused

### CTR Decryption Implementation

```python
def _decrypt_ctr(self, ciphertext: bytes, iv: bytes) -> bytes:
    """CTR mode decryption - counter mode"""
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    plaintext = bytearray()
    counter = int.from_bytes(iv, byteorder='big')
    
    for block in blocks:
        # Convert counter to bytes
        counter_bytes = counter.to_bytes(16, byteorder='big')
        # Encrypt counter
        encrypted_counter = self._xor_encrypt(counter_bytes, self.key)
        # XOR with ciphertext to get plaintext
        decrypted = self._xor_blocks(block, encrypted_counter)
        plaintext.extend(decrypted)
        counter += 1
    
    return bytes(plaintext)
```

**Key Points:**
- Counter-based stream cipher
- Fully parallelizable
- Random access to ciphertext
- Counter must never be reused

## Security Analysis

### Security Properties by Mode

| Mode | Confidentiality | Integrity | Pattern Hiding | Parallelization | Error Propagation |
|------|----------------|-----------|----------------|-----------------|------------------|
| ECB | Weak | None | None | Yes | None |
| CBC | Strong | None | Strong | No | Yes (2 blocks) |
| CFB | Strong | None | Strong | No | Limited |
| OFB | Strong | None | Strong | No | None |
| CTR | Strong | None | Strong | Yes | None |

### Known Vulnerabilities

**ECB:**
- Identical plaintext blocks produce identical ciphertext blocks
- Patterns in plaintext are visible in ciphertext
- Image encryption clearly shows image structure

**CBC:**
- Padding oracle attacks
- Requires IV to be unpredictable
- Sequential processing limits performance

**CFB:**
- Limited error propagation can be an issue in some contexts
- Less widely used than CBC

**OFB:**
- IV reuse leads to catastrophic failure
- Bit-flipping attacks possible
- Less common than CBC

**CTR:**
- Counter reuse leads to catastrophic failure
- Requires careful nonce management
- May leak timing information

## Performance Characteristics

### Encryption/Decryption Speed

| Mode | Speed | Parallelization | Memory Usage |
|------|-------|-----------------|--------------|
| ECB | Fastest | Full | Low |
| CBC | Medium | No | Low |
| CFB | Medium | No | Low |
| OFB | Medium | No | Low |
| CTR | Fast | Full | Low |

### Memory Requirements

- **ECB:** Minimal (no IV required)
- **CBC:** 16 bytes for IV
- **CFB:** 16 bytes for IV + feedback register
- **OFB:** 16 bytes for IV + feedback register
- **CTR:** 16 bytes for nonce + counter

## Usage Examples

### Example 1: ECB Mode

```python
from aes_core_simple import SimpleAES, SimpleFileCrypto, SimpleAESMode

# Generate key
key = SimpleFileCrypto.generate_key(256)

# Encrypt with ECB
aes = SimpleAES(key, SimpleAESMode.ECB)
plaintext = b"Hello, World!"
ciphertext, iv = aes.encrypt(plaintext, iv=None)

# Decrypt
decrypted = aes.decrypt(ciphertext, iv=None)
assert decrypted == plaintext
```

### Example 2: CBC Mode

```python
from aes_core_simple import SimpleAES, SimpleFileCrypto, SimpleAESMode

# Generate key and IV
key = SimpleFileCrypto.generate_key(256)
iv = SimpleFileCrypto.generate_iv()

# Encrypt with CBC
aes = SimpleAES(key, SimpleAESMode.CBC)
plaintext = b"Hello, World!"
ciphertext, iv = aes.encrypt(plaintext, iv)

# Decrypt
decrypted = aes.decrypt(ciphertext, iv)
assert decrypted == plaintext
```

### Example 3: CTR Mode

```python
from aes_core_simple import SimpleAES, SimpleFileCrypto, SimpleAESMode

# Generate key and nonce
key = SimpleFileCrypto.generate_key(256)
nonce = SimpleFileCrypto.generate_iv()  # Used as counter starting point

# Encrypt with CTR
aes = SimpleAES(key, SimpleAESMode.CTR)
plaintext = b"Hello, World!"
ciphertext, nonce = aes.encrypt(plaintext, nonce)

# Decrypt
decrypted = aes.decrypt(ciphertext, nonce)
assert decrypted == plaintext
```

### Example 4: File Encryption with Different Modes

```python
from file_crypto import FileCrypto
from aes_core import AESMode

# Generate key
key = FileCrypto.generate_key(256)

# Encrypt file with CBC
FileCrypto.encrypt_file("input.txt", "output_cbc.enc", key, AESMode.CBC)

# Encrypt file with CTR
FileCrypto.encrypt_file("input.txt", "output_ctr.enc", key, AESMode.CTR)

# Decrypt files
FileCrypto.decrypt_file("output_cbc.enc", "decrypted_cbc.txt", key, AESMode.CBC)
FileCrypto.decrypt_file("output_ctr.enc", "decrypted_ctr.txt", key, AESMode.CTR)
```

## Best Practices

### IV/Nonce Management

1. **Always use random IVs for CBC and CFB**
   ```python
   import os
   iv = os.urandom(16)  # Cryptographically secure random
   ```

2. **Never reuse IVs for the same key**
   - Each encryption should use a unique IV
   - Store IV with ciphertext (not secret)

3. **Counter management for CTR**
   - Use unique nonce for each message
   - Ensure counter doesn't wrap around
   - Store nonce with ciphertext

### Mode Selection Guidelines

**Use ECB when:**
- Encrypting small, fixed-size data
- Performance is critical
- Data has no repeating patterns
- Legacy compatibility required

**Use CBC when:**
- General-purpose encryption
- Compatibility with existing systems
- Random access not required
- Most common use case

**Use CFB when:**
- Need to encrypt partial blocks
- Self-synchronization is beneficial
- Stream cipher behavior needed

**Use OFB when:**
- Error propagation must be avoided
- Pre-generating keystream is beneficial
- Stream cipher behavior needed

**Use CTR when:**
- Performance is critical
- Random access to ciphertext needed
- Parallel processing available
- Disk encryption or similar applications

### Security Recommendations

1. **Never use ECB for sensitive data**
   - Pattern analysis can reveal information
   - Images encrypted with ECB are clearly visible

2. **Always authenticate ciphertext**
   - Use HMAC or authenticated encryption (AEAD)
   - Prevent tampering attacks

3. **Use appropriate key sizes**
   - AES-128: Generally sufficient
   - AES-192: Balanced security/performance
   - AES-256: Maximum security

4. **Handle errors properly**
   - Padding errors can leak information
   - Use constant-time comparisons
   - Implement proper error handling

## Conclusion

The AES decryption modes provide different trade-offs between security, performance, and functionality. Understanding these characteristics is essential for choosing the appropriate mode for your specific use case. The implementation provided here supports all five standard modes with proper error handling and security considerations.

For most applications, CBC mode is recommended as the default choice due to its widespread adoption and strong security properties. For high-performance applications requiring parallelization, CTR mode is often preferred. ECB should generally be avoided except for legacy compatibility or specific use cases where its limitations are acceptable.