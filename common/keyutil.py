"""Symmetric key material helpers."""

import os

VALID_KEY_SIZES = (128, 192, 256)
IV_SIZE = 16


def validate_key_size(key_size: int) -> int:
    """Validate a key size in bits and return it."""
    if key_size not in VALID_KEY_SIZES:
        raise ValueError("Key size must be 128, 192, or 256 bits")
    return key_size


def generate_key(key_size: int = 256) -> bytes:
    """Generate a random key of the given size in bits."""
    return os.urandom(validate_key_size(key_size) // 8)


def generate_iv() -> bytes:
    """Generate a random 16-byte initialization vector."""
    return os.urandom(IV_SIZE)
