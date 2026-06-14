from algorithms.encoding.common_wrappers import decode_text_codec, encode_text_codec

ALGORITHM_NAME = "Unicode Escape"
ALGORITHM_DESC = "Python 风格 Unicode 转义"


def encrypt(plaintext):
    return encode_text_codec(plaintext, 'unicode_escape')


def decrypt(ciphertext):
    return decode_text_codec(ciphertext, 'unicode_escape')
