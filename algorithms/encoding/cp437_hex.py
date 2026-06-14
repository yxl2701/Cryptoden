from algorithms.encoding.common_wrappers import decode_hex_with_codec, encode_hex_with_codec

ALGORITHM_NAME = "CP437 Hex"
ALGORITHM_DESC = "CP437 编码后的十六进制表示"


def encrypt(plaintext):
    return encode_hex_with_codec(plaintext, 'cp437')


def decrypt(ciphertext):
    return decode_hex_with_codec(ciphertext, 'cp437')
