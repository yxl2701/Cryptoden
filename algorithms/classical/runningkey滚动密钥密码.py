"""
Running Key密码 (滚动密钥密码)
=============================
使用一本书或长文本作为密钥的Vigenere变体

【加密原理】
密钥是一段长文本（如书中的段落）
明文与密钥逐字符进行Vigenere加密

【安全性】
如果密钥是随机且与明文等长，理论上不可破解
"""

def encrypt(plaintext, key=''):
    """Running Key加密"""
    if not key:
        return "错误: 请输入密钥（长文本）"
    
    plaintext = ''.join(c.upper() for c in plaintext if c.isalpha())
    key = ''.join(c.upper() for c in key if c.isalpha())
    
    if len(key) < len(plaintext):
        return f"错误: 密钥长度({len(key)})必须大于等于明文长度({len(plaintext)})"
    
    result = []
    for i, p in enumerate(plaintext):
        p_val = ord(p) - ord('A')
        k_val = ord(key[i]) - ord('A')
        c_val = (p_val + k_val) % 26
        result.append(chr(c_val + ord('A')))
    
    return ''.join(result)

def decrypt(ciphertext, key=''):
    """Running Key解密"""
    if not key:
        return "错误: 请输入密钥（长文本）"
    
    ciphertext = ''.join(c.upper() for c in ciphertext if c.isalpha())
    key = ''.join(c.upper() for c in key if c.isalpha())
    
    if len(key) < len(ciphertext):
        return f"错误: 密钥长度({len(key)})必须大于等于密文长度({len(ciphertext)})"
    
    result = []
    for i, c in enumerate(ciphertext):
        c_val = ord(c) - ord('A')
        k_val = ord(key[i]) - ord('A')
        p_val = (c_val - k_val) % 26
        result.append(chr(p_val + ord('A')))
    
    return ''.join(result)
