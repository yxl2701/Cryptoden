from algorithms.encoding.common_wrappers import decode_base64_variant, encode_base64_variant

ALGORITHM_NAME = "Base64 No Padding"
ALGORITHM_DESC = "去掉等号填充的 Base64 编码"


def encrypt(plaintext):
    return encode_base64_variant(plaintext, strip_padding=True)


def decrypt(ciphertext):
    return decode_base64_variant(ciphertext)
