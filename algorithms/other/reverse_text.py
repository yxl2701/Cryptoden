ALGORITHM_NAME = "Reverse Text"
ALGORITHM_DESC = "整段文本反转"


def encrypt(plaintext):
    return plaintext[::-1]


def decrypt(ciphertext):
    return ciphertext[::-1]
