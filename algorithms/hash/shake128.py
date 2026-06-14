try:
    from .common import digest_with_length
except ImportError:
    from algorithms.hash.common import digest_with_length

ALGORITHM_NAME = "SHAKE128"
ALGORITHM_DESC = "SHAKE128 可变长度哈希，默认输出 32 字节"


def encrypt(plaintext, length=32):
    try:
        return digest_with_length(plaintext, 'shake_128', length)
    except Exception as error:
        return f"哈希错误: {error}"
