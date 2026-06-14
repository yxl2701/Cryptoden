"""
仿射密码加密模块
================

【算法介绍】
仿射密码（Affine Cipher）是一种单表替换密码，是凯撒密码的推广形式。
它使用线性变换对字母进行加密，结合了乘法密码和加法密码。

【加密原理】
加密公式：E(x) = (ax + b) mod 26
其中：
- x 是明文字母在字母表中的位置（A=0, B=1, ..., Z=25）
- a 是乘法参数，必须与26互质（即gcd(a, 26) = 1）
- b 是加法参数（偏移量）
- mod 26 确保结果在字母表范围内

【参数a的限制】
a必须是1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25之一，
因为这些数与26互质（没有公因数）。

如果a与26不互质，则无法正确解密（会出现多个明文对应同一密文）。

【示例】
明文：HELLO
参数：a=5, b=8
加密过程：
  H(7)  → (5×7+8) mod 26 = 43 mod 26 = 17  → R
  E(4)  → (5×4+8) mod 26 = 28 mod 26 = 2   → C
  L(11) → (5×11+8) mod 26 = 63 mod 26 = 11 → L
  L(11) → (5×11+8) mod 26 = 63 mod 26 = 11 → L
  O(14) → (5×14+8) mod 26 = 78 mod 26 = 0  → A
密文：RCLLA

【安全性】
仿射密码比凯撒密码稍安全，但仍不安全：
1. 密钥空间较小：12×26 = 312种可能的密钥
2. 容易被频率分析破解
3. 已知明文攻击可以快速破解

【参数说明】
- a: 乘法参数，必须与26互质
- b: 加法参数，范围0-25
"""

def gcd(a, b):
    """
    计算最大公约数（欧几里得算法）
    
    用于验证参数a是否与26互质。
    
    参数:
        a, b: 两个整数
    
    返回:
        int: 最大公约数
    """
    while b:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    """计算 a 在模 m 下的乘法逆元"""
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


def encrypt(plaintext, a=5, b=8):
    """
    仿射密码加密函数
    
    使用公式 E(x) = (ax + b) mod 26 对明文进行加密。
    
    参数:
        plaintext (str): 明文
        a (int): 乘法参数，必须与26互质
        b (int): 加法参数
    
    返回:
        str: 密文，或错误信息
    
    加密过程:
        1. 检查参数a是否与26互质
        2. 遍历明文中的每个字符
        3. 对于字母字符：
           - 计算其在字母表中的位置x
           - 应用公式：(a*x + b) mod 26
           - 转换回字母
        4. 非字母字符保持不变
    
    示例:
        >>> encrypt("HELLO", 5, 8)
        'RCLLA'
    """
    # 检查参数a是否与26互质
    if gcd(a, 26) != 1:
        return "错误: 参数a必须与26互质"
    
    result = []
    
    for char in plaintext:
        if char.isalpha():
            if char.isupper():
                # 大写字母加密
                x = ord(char) - ord('A')
                encrypted = (a * x + b) % 26
                result.append(chr(encrypted + ord('A')))
            else:
                # 小写字母加密
                x = ord(char) - ord('a')
                encrypted = (a * x + b) % 26
                result.append(chr(encrypted + ord('a')))
        else:
            result.append(char)
    
    return ''.join(result)


def decrypt(ciphertext, a=5, b=8):
    """
    仿射密码解密函数（指定参数）
    
    使用公式 D(y) = a^(-1) × (y - b) mod 26 解密。
    
    参数:
        ciphertext (str): 密文
        a (int): 乘法参数
        b (int): 加法参数
    
    返回:
        str: 明文或错误信息
    """
    if gcd(a, 26) != 1:
        return "错误: 参数a必须与26互质"
    
    # 计算a的模26逆元
    a_inv = mod_inverse(a, 26)
    if a_inv is None:
        return "错误: 无法找到a的模逆"
    
    result = []
    
    for char in ciphertext:
        if char.isalpha():
            if char.isupper():
                y = ord(char) - ord('A')
                decrypted = (a_inv * (y - b)) % 26
                result.append(chr(decrypted + ord('A')))
            else:
                y = ord(char) - ord('a')
                decrypted = (a_inv * (y - b)) % 26
                result.append(chr(decrypted + ord('a')))
        else:
            result.append(char)
    
    return ''.join(result)



def decrypt_all(ciphertext):
    """
    爆破所有可能的参数组合
    
    尝试所有有效的参数a（与26互质）和所有参数b（0-25）。
    
    参数:
        ciphertext (str): 密文
    
    返回:
        str: 所有可能的解密结果
    """
    # 与26互质的数
    valid_a = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
    
    results = []
    
    for a in valid_a:
        for b in range(26):
            plaintext = decrypt(ciphertext, a, b)
            results.append(f"a={a:2d}, b={b:2d}: {plaintext}")
    
    return '\n'.join(results)

