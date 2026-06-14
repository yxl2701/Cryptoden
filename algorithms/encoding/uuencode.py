from algorithms.encoding.common_wrappers import decode_uu, encode_uu

ALGORITHM_NAME = "UUEncode"
ALGORITHM_DESC = "UUEncode 文本编码"


def encrypt(plaintext):
    return encode_uu(plaintext)


def decrypt(ciphertext):
    return decode_uu(ciphertext)
