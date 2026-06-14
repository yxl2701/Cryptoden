"""
Base62编码模块
==============

【编码原理】
Base62使用62个字符（0-9, A-Z, a-z）对数据进行编码。
相比Base64，不含特殊字符，适合URL和文件名。

字符集：0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz

【示例】
  输入: hello
  Base62: 7tQLfHzc
"""

ALGORITHM_NAME = "Base62"
ALGORITHM_DESC = "Base62编码，使用0-9A-Za-z，适合URL安全场景"

try:
    from .base_n import decode_to_bytes, encode_bytes
except ImportError:
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location('base_n', Path(__file__).with_name('base_n.py'))
    base_n = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(base_n)
    decode_to_bytes = base_n.decode_to_bytes
    encode_bytes = base_n.encode_bytes

BASE62_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'


def encrypt(plaintext):
    """Base62编码"""
    try:
        return encode_bytes(plaintext.encode('utf-8'), BASE62_ALPHABET)
    except Exception as e:
        return f"编码错误: {str(e)}"


def decrypt(ciphertext):
    """Base62解码"""
    try:
        return decode_to_bytes(ciphertext.strip(), BASE62_ALPHABET).decode('utf-8')
    except Exception as e:
        return f"解码错误: {str(e)}"
