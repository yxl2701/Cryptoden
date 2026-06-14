from algorithms.encoding.common_wrappers import decode_hex_with_codec, encode_hex_with_codec

ALGORITHM_NAME = "KOI8-R Hex"
ALGORITHM_DESC = "KOI8-R 编码后的十六进制表示"


def encrypt(plaintext):
    return encode_hex_with_codec(plaintext, 'koi8-r')


def decrypt(ciphertext):
    return decode_hex_with_codec(ciphertext, 'koi8-r')
