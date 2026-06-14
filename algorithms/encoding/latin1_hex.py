from algorithms.encoding.common_wrappers import decode_hex_with_codec, encode_hex_with_codec

ALGORITHM_NAME = "Latin1 Hex"
ALGORITHM_DESC = "Latin-1 编码后的十六进制表示"


def encrypt(plaintext):
    return encode_hex_with_codec(plaintext, 'latin-1')


def decrypt(ciphertext):
    return decode_hex_with_codec(ciphertext, 'latin-1')
