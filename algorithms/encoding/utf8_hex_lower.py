from algorithms.encoding.common_wrappers import decode_hex_lower_utf8, encode_hex_lower_utf8

ALGORITHM_NAME = "UTF-8 Hex Lower"
ALGORITHM_DESC = "UTF-8 小写十六进制表示"


def encrypt(plaintext):
    return encode_hex_lower_utf8(plaintext)


def decrypt(ciphertext):
    return decode_hex_lower_utf8(ciphertext)
