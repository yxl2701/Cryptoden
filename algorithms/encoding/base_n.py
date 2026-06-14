"""Shared helpers for byte-oriented base-N encodings."""


def encode_bytes(data: bytes, alphabet: str) -> str:
    """Encode bytes with the supplied alphabet, preserving leading zero bytes."""
    if not data:
        return ''

    base = len(alphabet)
    leading_zeros = _count_leading(data, 0)
    value = int.from_bytes(data, 'big')

    encoded = []
    while value:
        value, remainder = divmod(value, base)
        encoded.append(alphabet[remainder])

    return alphabet[0] * leading_zeros + ''.join(reversed(encoded))


def decode_to_bytes(text: str, alphabet: str) -> bytes:
    """Decode text with the supplied alphabet, preserving leading zero bytes."""
    if not text:
        return b''

    base = len(alphabet)
    char_map = {char: index for index, char in enumerate(alphabet)}
    leading_zeros = _count_leading(text, alphabet[0])

    value = 0
    for char in text:
        if char not in char_map:
            raise ValueError(f"非法字符: {char!r}")
        value = value * base + char_map[char]

    if value:
        byte_length = (value.bit_length() + 7) // 8
        decoded = value.to_bytes(byte_length, 'big')
    else:
        decoded = b''

    return b'\x00' * leading_zeros + decoded


def _count_leading(value, marker) -> int:
    count = 0
    for item in value:
        if item != marker:
            break
        count += 1
    return count
