from algorithms.encoding.common_wrappers import decode_hex_with_codec, encode_hex_with_codec

ALGORITHM_NAME = "UTF-8 BOM Hex"
ALGORITHM_DESC = "带 BOM 的 UTF-8 十六进制表示"


def encrypt(plaintext):
    return encode_hex_with_codec(plaintext, 'utf-8-sig')


def decrypt(ciphertext):
    return decode_hex_with_codec(ciphertext, 'utf-8-sig')
