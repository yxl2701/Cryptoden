try:
    from .common import adler32_digest
except ImportError:
    from algorithms.hash.common import adler32_digest

ALGORITHM_NAME = "Adler32"
ALGORITHM_DESC = "Adler-32 校验值"


def encrypt(plaintext):
    try:
        return adler32_digest(plaintext)
    except Exception as error:
        return f"校验错误: {error}"
