from algorithms.encoding.common_wrappers import decode_text_codec, encode_text_codec

ALGORITHM_NAME = "IDNA"
ALGORITHM_DESC = "域名 IDNA 编码"


def encrypt(plaintext):
    return encode_text_codec(plaintext, 'idna')


def decrypt(ciphertext):
    return decode_text_codec(ciphertext, 'idna')
