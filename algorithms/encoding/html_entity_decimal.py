from algorithms.encoding.common_wrappers import decode_html_entities, encode_html_entities

ALGORITHM_NAME = "HTML Entity Decimal"
ALGORITHM_DESC = "HTML 十进制实体编码"


def encrypt(plaintext):
    return encode_html_entities(plaintext)


def decrypt(ciphertext):
    return decode_html_entities(ciphertext)
