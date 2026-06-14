"""
维吉尼亚密码加密模块
====================

【算法介绍】
维吉尼亚密码（Vigenère Cipher）是由法国密码学家布莱斯·德·维吉尼亚（Blaise de Vigenère）
在16世纪发明的一种多表替换密码。它是对凯撒密码的改进，使用关键词来决定每个字母的偏移量。

维吉尼亚密码曾被称为"不可破译的密码"（le chiffre indéchiffrable），直到19世纪才被
弗里德里希·卡西斯基（Friedrich Kasiski）找到破解方法。

【加密原理】
维吉尼亚密码使用一个关键词，将关键词重复直到与明文长度相同。
然后对每个明文字母，使用对应关键词字母确定偏移量进行加密。

加密公式：C_i = (P_i + K_i) mod 26
其中：
- P_i 是明文第i个字母在字母表中的位置
- K_i 是关键词第i个字母在字母表中的位置（循环使用）
- C_i 是密文第i个字母

【示例】
明文：HELLO
关键词：KEY
扩展关键词：KEYKE

加密过程：
  H + K: (7 + 10) mod 26 = 17 → R
  E + E: (4 + 4) mod 26 = 8   → I
  L + Y: (11 + 24) mod 26 = 9 → J
  L + K: (11 + 10) mod 26 = 21 → V
  O + E: (14 + 4) mod 26 = 18 → S
密文：RIJVS

【安全性】
维吉尼亚密码比凯撒密码安全得多，因为：
1. 同一个字母在不同位置会被加密成不同字母
2. 频率分析更困难
但仍有弱点：
1. 关键词重复使用，可通过卡西斯基测试破解
2. 关键词长度可被推测

【参数说明】
- key: 加密密钥，由字母组成
"""

def encrypt(plaintext, key='KEY'):
    """
    维吉尼亚密码加密函数
    
    使用关键词对明文进行多表替换加密。
    
    参数:
        plaintext (str): 明文
        key (str): 密钥，由字母组成，默认为'KEY'
    
    返回:
        str: 密文
    
    加密过程:
        1. 将密钥转为大写
        2. 遍历明文中的每个字符
        3. 对于字母字符：
           - 计算密钥字母对应的偏移量（A=0, B=1, ..., Z=25）
           - 对明文字母进行偏移加密
           - 密钥索引递增（循环使用密钥）
        4. 非字母字符保持不变
    
    示例:
        >>> encrypt("HELLO", "KEY")
        'RIJVS'
        >>> encrypt("hello", "KEY")
        'rijvs'
    """
    if not key:
        key = 'KEY'
    
    key = key.upper()
    key_index = 0
    result = []
    
    for char in plaintext:
        if char.isalpha():
            # 计算当前密钥字母对应的偏移量
            # ord(key[key_index]) - ord('A') 得到密钥字母在字母表中的位置
            shift = ord(key[key_index % len(key)]) - ord('A')
            
            if char.isupper():
                # 大写字母加密
                encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
                result.append(encrypted_char)
            else:
                # 小写字母加密
                encrypted_char = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
                result.append(encrypted_char)
            
            # 密钥索引递增，使用取模实现循环
            key_index += 1
        else:
            # 非字母字符保持不变，不消耗密钥
            result.append(char)
    
    return ''.join(result)


def decrypt(ciphertext, key='KEY'):
    """
    维吉尼亚密码解密函数
    
    使用关键词对密文进行多表替换解密。
    
    参数:
        ciphertext (str): 密文
        key (str): 密钥，必须与加密时使用的密钥相同
    
    返回:
        str: 明文
    
    解密过程:
        1. 将密钥转为大写
        2. 遍历密文中的每个字符
        3. 对于字母字符：
           - 计算密钥字母对应的偏移量
           - 对密文字母进行反向偏移解密
           - 密钥索引递增
        4. 非字母字符保持不变
    
    示例:
        >>> decrypt("RIJVS", "KEY")
        'HELLO'
    """
    if not key:
        key = 'KEY'
    
    key = key.upper()
    key_index = 0
    result = []
    
    for char in ciphertext:
        if char.isalpha():
            # 计算当前密钥字母对应的偏移量
            shift = ord(key[key_index % len(key)]) - ord('A')
            
            if char.isupper():
                # 大写字母解密：减去偏移量
                decrypted_char = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
                result.append(decrypted_char)
            else:
                # 小写字母解密
                decrypted_char = chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
                result.append(decrypted_char)
            
            key_index += 1
        else:
            result.append(char)
    
    return ''.join(result)

