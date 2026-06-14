from algorithms.encoding.common_wrappers import decode_html_entities, encode_html_entities

ALGORITHM_NAME = "HTML Entity Hex"
ALGORITHM_DESC = "HTML 十六进制实体编码"


def encrypt(plaintext):
    return encode_html_entities(plaintext, hex_mode=True)


def decrypt(ciphertext):
    return decode_html_entities(ciphertext)
