from algorithms.encoding.common_wrappers import decode_base64_variant, encode_base64_variant

ALGORITHM_NAME = "Base64 URLSafe"
ALGORITHM_DESC = "URL 安全的 Base64 编码"


def encrypt(plaintext):
    return encode_base64_variant(plaintext, urlsafe=True)


def decrypt(ciphertext):
    return decode_base64_variant(ciphertext, urlsafe=True)
