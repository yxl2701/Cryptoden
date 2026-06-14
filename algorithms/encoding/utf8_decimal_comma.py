from algorithms.encoding.common_wrappers import decode_byte_values, encode_byte_values

ALGORITHM_NAME = "UTF-8 Decimal CSV"
ALGORITHM_DESC = "UTF-8 字节十进制逗号分隔表示"


def encrypt(plaintext):
    return encode_byte_values(plaintext, 10, separator=',')


def decrypt(ciphertext):
    return decode_byte_values(ciphertext, 10)
