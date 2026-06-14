from algorithms.encoding.common_wrappers import decode_text_codec, encode_text_codec

ALGORITHM_NAME = "Punycode"
ALGORITHM_DESC = "Punycode 编码"


def encrypt(plaintext):
    return encode_text_codec(plaintext, 'punycode')


def decrypt(ciphertext):
    return decode_text_codec(ciphertext, 'punycode')
