from algorithms.encoding.common_wrappers import decode_ascii85, encode_ascii85

ALGORITHM_NAME = "ASCII85"
ALGORITHM_DESC = "ASCII85 编码"


def encrypt(plaintext):
    return encode_ascii85(plaintext)


def decrypt(ciphertext):
    return decode_ascii85(ciphertext)
