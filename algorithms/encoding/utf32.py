from algorithms.encoding.common_wrappers import decode_hex_with_codec, encode_hex_with_codec

ALGORITHM_NAME = "UTF-32 Hex"
ALGORITHM_DESC = "UTF-32 十六进制表示"


def encrypt(plaintext):
    return encode_hex_with_codec(plaintext, 'utf-32')


def decrypt(ciphertext):
    return decode_hex_with_codec(ciphertext, 'utf-32')
