from algorithms.encoding.common_wrappers import decode_hex_with_codec, encode_hex_with_codec

ALGORITHM_NAME = "MacRoman Hex"
ALGORITHM_DESC = "MacRoman 编码后的十六进制表示"


def encrypt(plaintext):
    return encode_hex_with_codec(plaintext, 'mac_roman')


def decrypt(ciphertext):
    return decode_hex_with_codec(ciphertext, 'mac_roman')
