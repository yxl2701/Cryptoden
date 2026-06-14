"""
Base58编码模块
==============

【编码原理】
Base58是一种类似Base64的编码方式，但去除了容易混淆的字符：
0（数字零）、O（大写字母O）、I（大写字母I）、l（小写字母L）
以及Base64中的 + 和 /。

字符集：123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz

【特点】
1. 避免了易混淆字符，适合人工输入
2. 不含特殊字符，适合双击选择
3. 编码效率略低于Base64

【应用场景】
1. 比特币地址编码
2. 加密货币相关
3. CTF编码题

【示例】
  输入: hello
  Base58: Axk8Eh
"""

ALGORITHM_NAME = "Base58"
ALGORITHM_DESC = "Base58编码，避免易混淆字符，适合人工输入"

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

# Base58字符集（不含0/O/I/l）
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def encrypt(plaintext):
    """
    Base58编码

    将字符串编码为Base58格式。

    参数:
        plaintext (str): 明文

    返回:
        str: Base58编码结果

    示例:
        >>> encrypt("hello")
        'Axk8Eh'
    """
    try:
        return encode_bytes(plaintext.encode('utf-8'), BASE58_ALPHABET)
    except Exception as e:
        return f"编码错误: {str(e)}"


def decrypt(ciphertext):
    """
    Base58解码

    将Base58字符串还原为原始字符串。

    参数:
        ciphertext (str): Base58编码的字符串

    返回:
        str: 解码后的原始字符串

    示例:
        >>> decrypt("Axk8Eh")
        'hello'
    """
    try:
        return decode_to_bytes(ciphertext.strip(), BASE58_ALPHABET).decode('utf-8')
    except Exception as e:
        return f"解码错误: {str(e)}"
