"""Hexadecimal conversion helpers tolerant of copy-pasted input."""


def normalize_hex(hex_string: str) -> str:
    """Strip whitespace, an optional '0x' prefix and pad to an even length."""
    hex_string = ''.join(hex_string.split())
    if hex_string.startswith('0x'):
        hex_string = hex_string[2:]
    if not hex_string:
        raise ValueError("Empty hex string")
    if len(hex_string) % 2 != 0:
        hex_string = '0' + hex_string
    return hex_string


def hex_to_bytes(hex_string: str) -> bytes:
    """Convert a possibly loosely formatted hex string to bytes."""
    return bytes.fromhex(normalize_hex(hex_string))


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to a lowercase hex string."""
    return data.hex()
