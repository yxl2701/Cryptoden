from algorithms.other.common_transforms import even_odd_transpose_decrypt, even_odd_transpose_encrypt

ALGORITHM_NAME = "Even Odd Transpose"
ALGORITHM_DESC = "偶数位与奇数位拆分重排"


def encrypt(plaintext):
    return even_odd_transpose_encrypt(plaintext)


def decrypt(ciphertext):
    return even_odd_transpose_decrypt(ciphertext)
