"""
Beaufort密码 (博福特密码)
========================
一种多表替换密码，与Vigenere类似但使用减法

【加密原理】
C = (K - P) mod 26
P = (K - C) mod 26

加密和解密使用相同的操作

【示例】
密钥: KEY
明文: HELLO
密文: DBNLC
"""

def encrypt(plaintext, key='KEY'):
    """Beaufort加密（与解密相同）"""
    if not key:
        return "错误: 请输入密钥"
    
    plaintext = ''.join(c.upper() for c in plaintext if c.isalpha())
    key = ''.join(c.upper() for c in key if c.isalpha())
    
    result = []
    for i, p in enumerate(plaintext):
        k = key[i % len(key)]
        c_val = (ord(k) - ord(p)) % 26
        result.append(chr(c_val + ord('A')))
    
    return ''.join(result)

def decrypt(ciphertext, key='KEY'):
    """Beaufort解密（与加密相同）"""
    return encrypt(ciphertext, key)
