from algorithms.encoding.common_wrappers import decode_hex_with_codec, encode_hex_with_codec

ALGORITHM_NAME = "Base16"
ALGORITHM_DESC = "Base16 编码，等价于十六进制大写表示"


def encrypt(plaintext):
    return encode_hex_with_codec(plaintext, 'utf-8')


def decrypt(ciphertext):
    return decode_hex_with_codec(ciphertext, 'utf-8')
