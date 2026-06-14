"""
ROT13加密模块
==============

【加密原理】
ROT13是凯撒密码的一个特例，移位量为13。

加密公式:  E(x) = (x + 13) mod 26
解密公式:  D(x) = (x - 13) mod 26 = (x + 13) mod 26

【特殊性质】
ROT13的加密和解密是同一操作：
  因为字母表有26个字母，应用两次ROT13回到原文。
  ROT13(ROT13(x)) = x
  所以 encrypt() = decrypt()

【应用场景】
1. 论坛中隐藏剧透内容（非加密，只是防不经意看到）
2. 简单的文本混淆
3. CTF入门题

【示例】
  输入: hello
  ROT13: uryyb
  再应用一次: hello
"""


_ROT13_TABLE = str.maketrans(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
    'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm',
)


def encrypt(plaintext):
    """
    ROT13加密

    将每个字母移动13位。
    由于字母表26个字母，ROT13的加密和解密是同一函数。
    非字母字符保持不变。

    参数:
        plaintext (str): 明文

    返回:
        str: 密文

    示例:
        >>> encrypt("hello")
        'uryyb'
        >>> encrypt("uryyb")  # 再次应用即解密
        'hello'
    """
    return plaintext.translate(_ROT13_TABLE)


def decrypt(ciphertext):
    """
    ROT13解密

    ROT13的解密与加密相同（应用两次回到原文）。
    非字母字符保持不变。

    参数:
        ciphertext (str): 密文

    返回:
        str: 明文

    示例:
        >>> decrypt("uryyb")
        'hello'
    """
    # ROT13加解密相同，直接调用encrypt
    return encrypt(ciphertext)

