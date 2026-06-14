"""
Autokey密码 (自动密钥密码)
=========================
一种多表替换密码，密钥由预设密钥和明文组成

【加密原理】
密钥 = 预设密钥 + 明文（自动扩展）
明文与密钥逐字符相加模26

【示例】
预设密钥: QUEENLY
明文: ATTACK AT DAWN
完整密钥: QUEENLYATTACKATDAWN
"""

def encrypt(plaintext, key='KEY'):
    """Autokey加密"""
    if not key:
        return "错误: 请输入密钥"
    
    plaintext = ''.join(c.upper() for c in plaintext if c.isalpha())
    key = ''.join(c.upper() for c in key if c.isalpha())
    
    full_key = key + plaintext
    
    result = []
    for i, p in enumerate(plaintext):
        p_val = ord(p) - ord('A')
        k_val = ord(full_key[i]) - ord('A')
        c_val = (p_val + k_val) % 26
        result.append(chr(c_val + ord('A')))
    
    return ''.join(result)

def decrypt(ciphertext, key='KEY'):
    """Autokey解密"""
    if not key:
        return "错误: 请输入密钥"
    
    ciphertext = ''.join(c.upper() for c in ciphertext if c.isalpha())
    key = ''.join(c.upper() for c in key if c.isalpha())
    
    result = []
    full_key = key
    
    for i, c in enumerate(ciphertext):
        c_val = ord(c) - ord('A')
        k_val = ord(full_key[i]) - ord('A')
        p_val = (c_val - k_val) % 26
        plain_char = chr(p_val + ord('A'))
        result.append(plain_char)
        full_key += plain_char
    
    return ''.join(result)
