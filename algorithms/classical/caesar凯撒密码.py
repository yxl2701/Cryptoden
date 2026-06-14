"""
凯撒密码加密模块
================

【算法介绍】
凯撒密码（Caesar Cipher）是最古老的替换密码之一，由古罗马军事统帅朱利叶斯·凯撒
（Julius Caesar）在公元前58年左右发明并使用。凯撒用这种密码与他的将军们进行秘密通信。

凯撒密码的基本思想是将明文中的每个字母按照字母表顺序向后移动固定的位数。
例如，偏移量为3时，A变成D，B变成E，以此类推，Z变成C。

【加密原理】
加密公式：E(x) = (x + k) mod 26
其中：
- x 是明文字母在字母表中的位置（A=0, B=1, ..., Z=25）
- k 是偏移量（密钥）
- mod 26 确保结果在字母表范围内

【示例】
明文：HELLO
偏移量：3
加密过程：
  H(7) → (7+3) mod 26 = 10 → K
  E(4) → (4+3) mod 26 = 7  → H
  L(11) → (11+3) mod 26 = 14 → O
  L(11) → (11+3) mod 26 = 14 → O
  O(14) → (14+3) mod 26 = 17 → R
密文：KHOOR

【安全性】
凯撒密码非常不安全，因为：
1. 只有25种可能的密钥（偏移量1-25）
2. 容易被暴力破解
3. 容易被频率分析破解

【参数说明】
- shift: 偏移量，即字母移动的位数，范围1-25，默认为3
"""

def _shift_char(char, shift):
    if char.isupper():
        return chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
    if char.islower():
        return chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
    return char


def _shift_text(text, shift):
    shift = int(shift) % 26
    return ''.join(_shift_char(char, shift) for char in text)


def encrypt(plaintext, shift=3):
    """
    凯撒密码加密函数
    
    将明文中的每个字母按照指定的偏移量向后移动。
    非字母字符（如数字、标点符号、空格等）保持不变。
    
    参数:
        plaintext (str): 明文，待加密的原始文本
        shift (int): 偏移量，字母移动的位数，范围1-25，默认为3
    
    返回:
        str: 密文，加密后的文本
    
    加密过程:
        1. 遍历明文中的每个字符
        2. 如果是大写字母：
           - 计算其在字母表中的位置 (ord(char) - ord('A'))
           - 加上偏移量并取模26
           - 转换回大写字母
        3. 如果是小写字母：
           - 计算其在字母表中的位置 (ord(char) - ord('a'))
           - 加上偏移量并取模26
           - 转换回小写字母
        4. 非字母字符保持不变
    
    示例:
        >>> encrypt("HELLO", 3)
        'KHOOR'
        >>> encrypt("hello", 3)
        'khoor'
        >>> encrypt("Hello, World!", 3)
        'Khoor, Zruog!'
    """
    return _shift_text(plaintext, shift)


def decrypt(ciphertext, shift=3):
    """
    凯撒密码解密函数（指定偏移量）
    
    将密文中的每个字母按照指定的偏移量向前移动。
    这是加密的逆过程。
    
    参数:
        ciphertext (str): 密文，待解密的文本
        shift (int): 偏移量，字母移动的位数，范围1-25，默认为3
    
    返回:
        str: 明文，解密后的文本
    
    解密过程:
        1. 遍历密文中的每个字符
        2. 如果是大写字母：
           - 计算其在字母表中的位置
           - 减去偏移量并取模26（注意Python中负数取模结果为正）
           - 转换回大写字母
        3. 如果是小写字母：同样处理
        4. 非字母字符保持不变
    
    示例:
        >>> decrypt("KHOOR", 3)
        'HELLO'
        >>> decrypt("khoor", 3)
        'hello'
    """
    return _shift_text(ciphertext, -int(shift))



def decrypt_all(ciphertext):
    """
    爆破所有可能的偏移量
    
    由于凯撒密码只有25种可能的密钥，可以尝试所有偏移量进行解密。
    这是一种穷举攻击（Brute Force Attack）。
    
    参数:
        ciphertext (str): 密文
    
    返回:
        str: 所有可能的解密结果，每行一个
    
    爆破过程:
        1. 遍历偏移量1到25
        2. 对每个偏移量调用decrypt函数
        3. 将结果格式化输出
    
    示例:
        >>> decrypt_all("KHOOR")
        '偏移量  1: JGNNQ\\n偏移量  2: IFMMP\\n...\\n偏移量  3: HELLO\\n...'
    
    实际应用:
        用户可以从输出中寻找有意义的明文，从而确定正确的偏移量。
    """
    results = []
    
    # 遍历所有可能的偏移量（1-25）
    for shift in range(1, 26):
        plaintext = decrypt(ciphertext, shift)
        # 格式化输出：偏移量右对齐占2位，便于阅读
        results.append(f"偏移量 {shift:2d}: {plaintext}")
    
    return '\n'.join(results)

