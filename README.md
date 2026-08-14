# Cryptography Projects Suite

Complete implementations of advanced cryptographic systems for ECE applications.

## Projects Included

### 1. AES Encryption/Decryption System
- **AES-256** implementation with hardware acceleration
- Python/C++ software implementations
- FPGA hardware acceleration
- PyQt5 GUI for encryption/decryption
- File and text encryption support
- Performance benchmarking

### 2. RSA Cryptography System
- Complete RSA implementation with key generation
- Large integer arithmetic
- Prime number generation algorithms
- Digital signatures
- Secure key exchange
- Python/C++ implementations
- GUI for key management and operations

## Project Structure

```
cryptography_projects/
├── aes_system/
│   ├── python/          # Python AES implementation
│   ├── cpp/             # C++ AES implementation
│   ├── fpga/            # FPGA hardware acceleration
│   ├── gui/             # PyQt5 GUI
│   └── tests/           # Test suites
├── rsa_system/
│   ├── python/          # Python RSA implementation
│   ├── cpp/             # C++ RSA implementation
│   ├── gui/             # PyQt5 GUI
│   └── tests/           # Test suites
└── docs/                # Documentation
```

## Technologies Used

- **Languages**: Python, C++, Verilog
- **Libraries**: NumPy, PyQt5, GMP, Cryptography libraries
- **Hardware**: FPGA (Xilinx/Intel)
- **GUI**: PyQt5
- **Build**: CMake, Make, Python setuptools

## Getting Started

### AES System
```bash
cd aes_system/python
python aes_gui.py
```

### RSA System
```bash
cd rsa_system/python
python rsa_gui.py
```

## Features

### AES System
- AES-128, AES-192, AES-256 support
- ECB, CBC, CFB, OFB, CTR modes
- Hardware acceleration option
- File encryption/decryption
- Text encryption/decryption
- Performance comparison (software vs hardware)

### RSA System
- Variable key size (1024-4096 bits)
- Key generation (Miller-Rabin primality test)
- Encryption/decryption
- Digital signatures
- Key exchange protocols
- Performance benchmarking

## Documentation

- AES implementation details: `docs/aes_implementation.md`
- RSA implementation details: `docs/rsa_implementation.md`
- FPGA design: `docs/fpga_design.md`
- API documentation: `docs/api_reference.md`

## License

MIT License - See LICENSE file for details

## Security Note

These implementations are for educational purposes. For production use, use well-tested cryptographic libraries like OpenSSL, Libsodium, or Cryptography.io.
