try:
    from .common import digest
except ImportError:
    from algorithms.hash.common import digest

ALGORITHM_NAME = "SHA3-224"
ALGORITHM_DESC = "SHA3-224 哈希算法"


def encrypt(plaintext):
    try:
        return digest(plaintext, 'sha3_224')
    except Exception as error:
        return f"哈希错误: {error}"
