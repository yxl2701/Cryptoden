from algorithms.encoding.common_wrappers import decode_byte_values, encode_byte_values

ALGORITHM_NAME = "UTF-8 Octal"
ALGORITHM_DESC = "UTF-8 字节八进制表示"


def encrypt(plaintext):
    return encode_byte_values(plaintext, 8)


def decrypt(ciphertext):
    return decode_byte_values(ciphertext, 8)
