"""Block and byte-string helpers shared by the AES implementations."""

from typing import Callable, List, Optional, Tuple

BLOCK_SIZE = 16


def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> List[bytes]:
    """Split data into block_size chunks; the final chunk may be short."""
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]


def zero_pad(block: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Right-pad a short block with null bytes."""
    if len(block) >= block_size:
        return block
    return block + b'\x00' * (block_size - len(block))


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Append PKCS#7 padding, always adding at least one byte."""
    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length] * padding_length)


def strip_null_padding(data: bytes) -> bytes:
    """Remove trailing null bytes added by zero_pad."""
    return data.rstrip(b'\x00')


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """XOR two byte strings up to the length of the first one."""
    return bytes(a ^ b for a, b in zip(left, right))


def repeat_to_length(data: bytes, length: int) -> bytes:
    """Repeat data cyclically until it is exactly length bytes long."""
    return (data * ((length // len(data)) + 1))[:length]


def xor_with_keystream(data: bytes, key: bytes, iv: Optional[bytes] = None) -> bytes:
    """XOR data with the key (and IV when given), both repeated cyclically."""
    keystream = repeat_to_length(key, len(data))
    if iv is not None:
        iv_stream = repeat_to_length(iv, len(data))
        keystream = xor_bytes(keystream, iv_stream)
    return xor_bytes(data, keystream)


def transform_blocks(data: bytes, initial_state,
                     step: Callable[[bytes, object], Tuple[bytes, object]],
                     block_size: int = BLOCK_SIZE) -> bytes:
    """Run a chaining mode over data.

    ``step`` receives a zero-padded block plus the current chaining state and
    returns the output block together with the state for the next block.
    """
    output = bytearray()
    state = initial_state
    for block in split_blocks(data, block_size):
        output_block, state = step(zero_pad(block, block_size), state)
        output.extend(output_block)
    return bytes(output)
