from algorithms.encoding.common_wrappers import decode_hex_with_codec, encode_hex_with_codec

ALGORITHM_NAME = "EUC-JP Hex"
ALGORITHM_DESC = "EUC-JP 编码后的十六进制表示"


def encrypt(plaintext):
    return encode_hex_with_codec(plaintext, 'euc_jp')


def decrypt(ciphertext):
    return decode_hex_with_codec(ciphertext, 'euc_jp')
