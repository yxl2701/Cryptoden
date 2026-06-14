from algorithms.encoding.common_wrappers import decode_utf9, encode_utf9

ALGORITHM_NAME = "UTF9"
ALGORITHM_DESC = "实验性 9 位字节组文本表示"


def encrypt(plaintext):
    return encode_utf9(plaintext)


def decrypt(ciphertext):
    return decode_utf9(ciphertext)
