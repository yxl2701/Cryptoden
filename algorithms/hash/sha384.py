try:
    from .common import digest
except ImportError:
    from algorithms.hash.common import digest

ALGORITHM_NAME = "SHA384"
ALGORITHM_DESC = "SHA-384 哈希算法"


def encrypt(plaintext):
    try:
        return digest(plaintext, 'sha384')
    except Exception as error:
        return f"哈希错误: {error}"
