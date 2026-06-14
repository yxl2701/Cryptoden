"""
埃特巴什码加密模块
==================

【算法介绍】
埃特巴什码（Atbash Cipher）是一种非常古老的替换密码，其名称来源于希伯来字母表
的第一个字母Aleph（א）和最后一个字母Tav（ת）。

埃特巴什码最初用于希伯来字母表，后来也应用于拉丁字母表。
在《圣经》中就有使用埃特巴什码的例子。

【加密原理】
埃特巴什码是一种简单的单表替换密码，将字母表反转：
- A ↔ Z
- B ↔ Y
- C ↔ X
- ...
- M ↔ N

数学公式：E(x) = (25 - x) 或 E(x) = ('Z' - x)
其中x是字母在字母表中的位置（A=0, B=1, ..., Z=25）

【示例】
明文：HELLO
加密过程：
  H(7)  → 25-7=18  → S
  E(4)  → 25-4=21  → V
  L(11) → 25-11=14 → O
  L(11) → 25-11=14 → O
  O(14) → 25-14=11 → L
密文：SVOOL

【特点】
1. 加密和解密过程完全相同（自反性）
2. 没有密钥，安全性极低
3. 常作为其他密码的一部分使用

【安全性】
埃特巴什码非常不安全：
1. 没有密钥，任何人都可以解密
2. 只有26种字母对应关系，固定不变
3. 容易被频率分析破解
"""

def _atbash_char(char):
    if char.isupper():
        return chr(ord('Z') - (ord(char) - ord('A')))
    if char.islower():
        return chr(ord('z') - (ord(char) - ord('a')))
    return char


def _atbash_text(text):
    return ''.join(_atbash_char(char) for char in text)


def encrypt(plaintext):
    """
    埃特巴什码加密函数
    
    将字母表反转进行替换。由于算法的自反性，加密和解密使用同一函数。
    
    参数:
        plaintext (str): 明文
    
    返回:
        str: 密文
    
    加密过程:
        1. 遍历明文中的每个字符
        2. 对于大写字母：
           - 计算其与'Z'的距离（反转位置）
           - ord('Z') - (ord(char) - ord('A'))
        3. 对于小写字母：同样处理
        4. 非字母字符保持不变
    
    示例:
        >>> encrypt("HELLO")
        'SVOOL'
        >>> encrypt("hello")
        'svool'
        >>> encrypt("SVOOL")  # 再次加密等于解密
        'HELLO'
    """
    return _atbash_text(plaintext)


def decrypt(ciphertext):
    """
    埃特巴什码解密函数
    
    由于算法的自反性，解密与加密使用相同的操作。
    
    参数:
        ciphertext (str): 密文
    
    返回:
        str: 明文
    
    示例:
        >>> decrypt("SVOOL")
        'HELLO'
    """
    return _atbash_text(ciphertext)

