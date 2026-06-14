from algorithms.encoding.common_wrappers import decode_hex_with_codec, encode_hex_with_codec

ALGORITHM_NAME = "UTF-7 Hex"
ALGORITHM_DESC = "UTF-7 编码后的十六进制表示"


def encrypt(plaintext):
    return encode_hex_with_codec(plaintext, 'utf-7')


def decrypt(ciphertext):
    return decode_hex_with_codec(ciphertext, 'utf-7')
