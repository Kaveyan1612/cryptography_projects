"""Big-endian integer/bytes conversions used by the RSA implementation."""


def byte_length(value: int) -> int:
    """Number of bytes needed to represent value."""
    return (value.bit_length() + 7) // 8


def int_to_bytes(value: int, length: int = None) -> bytes:
    """Convert an integer to big-endian bytes, minimal length by default."""
    return value.to_bytes(byte_length(value) if length is None else length,
                          byteorder='big')


def bytes_to_int(data: bytes) -> int:
    """Convert big-endian bytes to an integer."""
    return int.from_bytes(data, byteorder='big')
