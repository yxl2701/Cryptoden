try:
    from .common import digest
except ImportError:
    from algorithms.hash.common import digest

ALGORITHM_NAME = "SHA224"
ALGORITHM_DESC = "SHA-224 哈希算法"


def encrypt(plaintext):
    try:
        return digest(plaintext, 'sha224')
    except Exception as error:
        return f"哈希错误: {error}"
