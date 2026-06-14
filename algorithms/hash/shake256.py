try:
    from .common import digest_with_length
except ImportError:
    from algorithms.hash.common import digest_with_length

ALGORITHM_NAME = "SHAKE256"
ALGORITHM_DESC = "SHAKE256 可变长度哈希，默认输出 64 字节"


def encrypt(plaintext, length=64):
    try:
        return digest_with_length(plaintext, 'shake_256', length)
    except Exception as error:
        return f"哈希错误: {error}"
