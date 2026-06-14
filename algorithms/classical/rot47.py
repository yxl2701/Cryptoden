"""
ROT47加密模块
==============

【算法介绍】
ROT47是ROT13的扩展版本，适用于所有可打印ASCII字符（编码33-126）。
它将每个可打印ASCII字符移动47位，形成一种简单的混淆编码。

【加密原理】
ROT47作用于ASCII码33到126之间的所有可打印字符：
  E(x) = 33 + ((x - 33 + 47) % 94)
其中94 = 126 - 33 + 1，即可打印字符总数。

与ROT13不同，ROT47可以处理数字、标点符号等非字母字符。

【特殊性质】
与ROT13一样，ROT47的加密和解密是同一操作：
  ROT47(ROT47(x)) = x
所以 encrypt() = decrypt()

【应用场景】
1. CTF入门题
2. 简单的文本混淆
3. 隐藏代码片段

【示例】
  输入: Hello World!
  ROT47: w6==@ (@C=5P
  再应用一次: Hello World!

  输入: flag{rot47_is_easy}
  ROT47: 7=28oC@Ecf:D:JD
"""


_ROT47_TABLE = str.maketrans(
    ''.join(chr(code) for code in range(33, 127)),
    ''.join(chr(33 + (code - 33 + 47) % 94) for code in range(33, 127)),
)


def encrypt(plaintext):
    """
    ROT47加密

    将每个可打印ASCII字符（33-126）移动47位。
    非可打印字符保持不变。

    参数:
        plaintext (str): 明文

    返回:
        str: 密文

    示例:
        >>> encrypt("Hello World!")
        'w6==@ (@C=5P'
        >>> encrypt("w6==@ (@C=5P")
        'Hello World!'
    """
    return plaintext.translate(_ROT47_TABLE)


def decrypt(ciphertext):
    """
    ROT47解密

    ROT47的解密与加密相同（应用两次回到原文）。

    参数:
        ciphertext (str): 密文

    返回:
        str: 明文
    """
    return encrypt(ciphertext)
