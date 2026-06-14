from algorithms.encoding.common_wrappers import decode_hex_with_codec, encode_hex_with_codec

ALGORITHM_NAME = "Shift-JIS Hex"
ALGORITHM_DESC = "Shift-JIS 编码后的十六进制表示"


def encrypt(plaintext):
    return encode_hex_with_codec(plaintext, 'shift_jis')


def decrypt(ciphertext):
    return decode_hex_with_codec(ciphertext, 'shift_jis')
