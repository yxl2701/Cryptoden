from algorithms.encoding.common_wrappers import decode_hex_with_codec, encode_hex_with_codec

ALGORITHM_NAME = "GB2312 Hex"
ALGORITHM_DESC = "GB2312 编码后的十六进制表示"


def encrypt(plaintext):
    return encode_hex_with_codec(plaintext, 'gb2312')


def decrypt(ciphertext):
    return decode_hex_with_codec(ciphertext, 'gb2312')
