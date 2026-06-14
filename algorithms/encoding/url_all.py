from algorithms.encoding.common_wrappers import decode_url_all, encode_url_all

ALGORITHM_NAME = "URL Full Encode"
ALGORITHM_DESC = "对所有非安全字符进行 URL 编码"


def encrypt(plaintext):
    return encode_url_all(plaintext)


def decrypt(ciphertext):
    return decode_url_all(ciphertext)
