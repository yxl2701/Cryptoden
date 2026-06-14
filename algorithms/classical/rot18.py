"""
ROT18加密模块
==============

【算法介绍】
ROT18是ROT5和ROT13的组合，同时作用于字母和数字。
- 字母部分：ROT13（移动13位）
- 数字部分：ROT5（移动5位）
- 其他字符保持不变

【加密原理】
  E(letter) = (letter + 13) % 26
  E(digit)  = (digit + 5) % 10

【特殊性质】
与ROT13一样，ROT18的加密和解密是同一操作：
  ROT18(ROT18(x)) = x
所以 encrypt() = decrypt()

【应用场景】
1. 同时混淆字母和数字
2. CTF入门题

【示例】
  输入: Hello123
  ROT18: Uryyb678
"""


_ROT18_TABLE = str.maketrans(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
    'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm5678901234',
)


def encrypt(plaintext):
    """
    ROT18加密

    字母移动13位，数字移动5位。
    其他字符保持不变。

    参数:
        plaintext (str): 明文

    返回:
        str: 密文

    示例:
        >>> encrypt("Hello123")
        'Uryyb678'
        >>> encrypt("Uryyb678")
        'Hello123'
    """
    return plaintext.translate(_ROT18_TABLE)


def decrypt(ciphertext):
    """
    ROT18解密

    ROT18的解密与加密相同。

    参数:
        ciphertext (str): 密文

    返回:
        str: 明文
    """
    return encrypt(ciphertext)
