from algorithms.encoding.common_wrappers import decode_text_codec, encode_text_codec

ALGORITHM_NAME = "Raw Unicode Escape"
ALGORITHM_DESC = "Raw Unicode Escape 编码"


def encrypt(plaintext):
    return encode_text_codec(plaintext, 'raw_unicode_escape')


def decrypt(ciphertext):
    return decode_text_codec(ciphertext, 'raw_unicode_escape')
