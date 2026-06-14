try:
    from .common import digest
except ImportError:
    from algorithms.hash.common import digest

ALGORITHM_NAME = "BLAKE2b"
ALGORITHM_DESC = "BLAKE2b 哈希算法"


def encrypt(plaintext):
    try:
        return digest(plaintext, 'blake2b')
    except Exception as error:
        return f"哈希错误: {error}"
