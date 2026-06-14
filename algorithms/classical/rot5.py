"""
ROT5加密模块
==============

【算法介绍】
ROT5是ROT13的数字版本，只对数字字符（0-9）进行移位。
每个数字向后移动5位，超过9则循环回到0。

【加密原理】
  E(x) = (x + 5) % 10

【特殊性质】
与ROT13一样，ROT5的加密和解密是同一操作：
  ROT5(ROT5(x)) = x
所以 encrypt() = decrypt()

【应用场景】
1. 隐藏电话号码、数字ID
2. 配合ROT13使用（ROT18 = ROT5 + ROT13）
3. CTF入门题

【示例】
  输入: 12345
  ROT5: 67890
  输入: My PIN is 1234
  ROT5: My PIN is 6789
"""


_ROT5_TABLE = str.maketrans('0123456789', '5678901234')


def encrypt(plaintext):
    """
    ROT5加密

    将每个数字字符移动5位。
    非数字字符保持不变。

    参数:
        plaintext (str): 明文

    返回:
        str: 密文

    示例:
        >>> encrypt("12345")
        '67890'
        >>> encrypt("67890")
        '12345'
    """
    return plaintext.translate(_ROT5_TABLE)


def decrypt(ciphertext):
    """
    ROT5解密

    ROT5的解密与加密相同。

    参数:
        ciphertext (str): 密文

    返回:
        str: 明文
    """
    return encrypt(ciphertext)
