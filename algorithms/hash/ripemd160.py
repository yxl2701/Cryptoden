try:
    from .common import digest
except ImportError:
    from algorithms.hash.common import digest

ALGORITHM_NAME = "RIPEMD160"
ALGORITHM_DESC = "RIPEMD-160 哈希算法，依赖当前 OpenSSL 支持"


def encrypt(plaintext):
    try:
        return digest(plaintext, 'ripemd160')
    except Exception as error:
        return f"哈希错误: {error}"
