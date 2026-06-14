from algorithms.encoding.common_wrappers import decode_hex_with_codec, encode_hex_with_codec

ALGORITHM_NAME = "GBK Hex"
ALGORITHM_DESC = "GBK 编码后的十六进制表示"


def encrypt(plaintext):
    return encode_hex_with_codec(plaintext, 'gbk')


def decrypt(ciphertext):
    return decode_hex_with_codec(ciphertext, 'gbk')
