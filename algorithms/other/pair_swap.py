from algorithms.other.common_transforms import pairwise_swap_text

ALGORITHM_NAME = "Pair Swap"
ALGORITHM_DESC = "相邻字符两两交换"


def encrypt(plaintext):
    return pairwise_swap_text(plaintext)


def decrypt(ciphertext):
    return pairwise_swap_text(ciphertext)
