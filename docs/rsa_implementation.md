# RSA Implementation Documentation

## Overview
This document describes the complete implementation of the RSA (Rivest-Shamir-Adleman) public-key cryptosystem, including key generation, encryption, decryption, and digital signatures.

## Architecture

### Software Components

#### 1. RSA Core (`rsa_core.py`)
The core RSA implementation with the following features:
- **Key Sizes**: 1024, 2048, 3072, 4096 bits
- **Key Generation**: Miller-Rabin primality testing
- **Encryption/Decryption**: Standard RSA operations
- **Digital Signatures**: SHA-256 based signatures
- **CRT Optimization**: Chinese Remainder Theorem for faster decryption
- **Key Exchange**: Diffie-Hellman style key exchange

#### 2. RSA GUI (`rsa_gui.py`)
Graphical interface for RSA operations:
- Key generation and management
- Encryption/decryption operations
- Digital signature creation and verification
- Performance benchmarking
- Key export/import

## RSA Algorithm Details

### Key Generation Process
1. **Generate Prime Numbers**:
   - Generate two large random primes p and q
   - Use Miller-Rabin primality test
   - Ensure p ≠ q

2. **Calculate Modulus**:
   - n = p × q
   - This is the RSA modulus

3. **Calculate Euler's Totient**:
   - φ(n) = (p-1) × (q-1)

4. **Choose Public Exponent**:
   - Standard e = 65537 (2^16 + 1)
   - Must be coprime to φ(n)

5. **Calculate Private Exponent**:
   - d = e^(-1) mod φ(n)
   - Using extended Euclidean algorithm

6. **CRT Parameters** (for optimization):
   - dP = d mod (p-1)
   - dQ = d mod (q-1)
   - qInv = q^(-1) mod p

### Encryption Process
```
ciphertext = plaintext^e mod n
```

### Decryption Process (Standard)
```
plaintext = ciphertext^d mod n
```

### Decryption Process (CRT Optimized)
```
m1 = ciphertext^dP mod p
m2 = ciphertext^dQ mod q
h = qInv × (m1 - m2) mod p
plaintext = m2 + h × q
```

### Digital Signature Creation
1. Hash the message using SHA-256
2. Convert hash to integer
3. Sign: signature = hash^d mod n
4. Output: (message, signature)

### Digital Signature Verification
1. Hash the message using SHA-256
2. Verify: hash = signature^e mod n
3. Compare computed hash with original hash

## Primality Testing

### Miller-Rabin Algorithm
The Miller-Rabin primality test is used for prime generation:

1. **Setup**: Write n-1 as 2^r × d where d is odd
2. **Test Rounds**: Perform k rounds of testing
3. **Each Round**:
   - Choose random witness a
   - Compute x = a^d mod n
   - If x = 1 or x = n-1, probably prime
   - Square x up to r-1 times
   - If x = n-1, probably prime
   - Otherwise, composite

### Accuracy
- **40 rounds**: Error probability < 2^(-80)
- **Cryptographically secure**: Sufficient for key generation

## Modular Arithmetic

### Extended Euclidean Algorithm
Used to calculate modular inverses:
```
gcd(a, m) = a × x + m × y
If gcd(a, m) = 1, then x is modular inverse of a mod m
```

### Fast Modular Exponentiation
Square-and-multiply algorithm for efficient exponentiation:
```
result = 1
while exponent > 0:
    if exponent is odd:
        result = (result × base) mod n
    base = (base × base) mod n
    exponent = exponent // 2
```

## Performance Characteristics

### Key Generation Performance
- **1024-bit**: ~0.1-0.5 seconds
- **2048-bit**: ~0.5-2 seconds
- **3072-bit**: ~2-5 seconds
- **4096-bit**: ~5-15 seconds

### Encryption Performance
- **1024-bit**: ~0.001-0.005 seconds per operation
- **2048-bit**: ~0.005-0.02 seconds per operation
- **3072-bit**: ~0.02-0.05 seconds per operation
- **4096-bit**: ~0.05-0.1 seconds per operation

### Decryption Performance
- **Standard**: 10-20x slower than encryption
- **CRT Optimized**: 4-8x faster than standard
- **Overall**: Still slower than encryption

### CRT Speedup
- **Theoretical**: 4x speedup
- **Practical**: 3-4x speedup
- **Impact**: Significant for large key sizes

## Security Considerations

### Key Size Recommendations
- **1024-bit**: Minimum (deprecated)
- **2048-bit**: Recommended until 2030
- **3072-bit**: Future-proof
- **4096-bit**: High-security applications

### Side-Channel Attacks
- **Timing Attacks**: Mitigated with constant-time operations
- **Power Analysis**: Requires hardware countermeasures
- **Cache Attacks**: Requires constant-time memory access

### Implementation Security
- **Secure Random Number Generation**: Use system CSPRNG
- **Key Storage**: Use secure key management
- **Memory Security**: Zero sensitive data after use
- **Error Handling**: Don't leak information through errors

## Padding Schemes

### PKCS#1 v1.5
- Simple padding scheme
- Format: 0x00 || 0x02 || random padding || 0x00 || message
- Vulnerable to certain attacks
- Widely supported

### OAEP (Optimal Asymmetric Encryption Padding)
- More secure padding
- Uses hash functions
- Proven secure in random oracle model
- Recommended for new applications

### PSS (Probabilistic Signature Scheme)
- Secure padding for signatures
- Salted hashing
- Proven secure
- Recommended for new applications

## Key Management

### Key Storage
- **Public Keys**: Can be freely distributed
- **Private Keys**: Must be kept secret
- **Formats**: PEM, DER, PKCS#8, PKCS#12

### Key Distribution
- **Certificates**: X.509 certificates for public keys
- **Key Servers**: Public key infrastructure
- **Direct Exchange**: Secure channels

### Key Rotation
- **Periodic Rotation**: Regular key updates
- **Compromise Response**: Immediate rotation if suspected
- **Planning**: Manage key lifecycle

## Testing

### Unit Tests
```python
from rsa_core import RSA

# Test key generation
rsa = RSA(2048)
public_key, private_key = rsa.generate_keypair()

# Test encryption/decryption
message = 123456789
ciphertext = rsa.encrypt(message, public_key)
decrypted = rsa.decrypt(ciphertext, private_key)

assert decrypted == message
```

### Signature Tests
```python
# Test signing/verification
message = "Important message"
signature, hash_algo = rsa.sign(message, private_key)
is_valid = rsa.verify(message, signature, public_key, hash_algo)

assert is_valid == True
```

### Performance Tests
```python
from rsa_core import RSABenchmark

# Benchmark key generation
results = RSABenchmark.benchmark_key_generation(2048, 10)
print(f"Average time: {results['average_time']:.4f}s")
```

## Usage Examples

### Python Usage
```python
from rsa_core import RSA

# Generate keys
rsa = RSA(2048)
public_key, private_key = rsa.generate_keypair()

# Encrypt data
plaintext = b"Secret message"
encrypted = rsa.encrypt_bytes(plaintext, public_key)

# Decrypt data
decrypted = rsa.decrypt_bytes(encrypted, private_key)
```

### Digital Signatures
```python
# Sign message
message = "Contract agreement"
signature, hash_algo = rsa.sign(message, private_key)

# Verify signature
is_valid = rsa.verify(message, signature, public_key, hash_algo)
```

### GUI Usage
```bash
cd rsa_system/gui
python rsa_gui.py
```

## Comparison with Standard Libraries

### Python Cryptography Library
- **Performance**: Similar for operations
- **Features**: More comprehensive
- **Security**: More thoroughly tested
- **Purpose**: Production use

### OpenSSL
- **Performance**: Much faster (C implementation)
- **Features**: Extensive cryptographic capabilities
- **Security**: Battle-tested
- **Purpose**: Production use

## Future Enhancements

### Algorithm Improvements
- **Multi-prime RSA**: More than two primes
- **Side-channel protection**: Constant-time operations
- **Memory protection**: Secure memory handling

### Performance
- **GPU Acceleration**: Parallel processing
- **ASIC Implementation**: Hardware acceleration
- **Cloud Integration**: Distributed computing

### Features
- **Key Recovery**: Secret sharing schemes
- **Threshold Cryptography**: Multi-party signatures
- **Post-quantum**: Lattice-based alternatives

## References
- PKCS#1: RSA Cryptography Standard
- RFC 8017: PKCS#1 v2.2
- NIST SP 800-57: Key Management
- Handbook of Applied Cryptography

## Conclusion
This RSA implementation provides a complete, educational implementation of the RSA cryptosystem with all standard operations. While not intended for production use, it serves as an excellent learning tool for understanding public-key cryptography and digital signatures.
