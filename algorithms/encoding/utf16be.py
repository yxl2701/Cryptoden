from algorithms.encoding.common_wrappers import decode_hex_with_codec, encode_hex_with_codec

ALGORITHM_NAME = "UTF-16BE Hex"
ALGORITHM_DESC = "UTF-16BE 十六进制表示"


def encrypt(plaintext):
    return encode_hex_with_codec(plaintext, 'utf-16-be')


def decrypt(ciphertext):
    return decode_hex_with_codec(ciphertext, 'utf-16-be')
