try:
    from .common import crc32_digest
except ImportError:
    from algorithms.hash.common import crc32_digest

ALGORITHM_NAME = "CRC32"
ALGORITHM_DESC = "CRC32 校验值"


def encrypt(plaintext):
    try:
        return crc32_digest(plaintext)
    except Exception as error:
        return f"校验错误: {error}"
