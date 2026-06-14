try:
    from .common import digest
except ImportError:
    from algorithms.hash.common import digest

ALGORITHM_NAME = "BLAKE2s"
ALGORITHM_DESC = "BLAKE2s 哈希算法"


def encrypt(plaintext):
    try:
        return digest(plaintext, 'blake2s')
    except Exception as error:
        return f"哈希错误: {error}"
