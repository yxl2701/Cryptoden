"""
Gronsfeld密码 (格罗斯菲尔德密码)
================================
Vigenere密码的变体，使用数字作为密钥

【加密原理】
密钥是数字序列，每个数字表示位移量
与Vigenere类似，但密钥是数字而非字母

【示例】
密钥: 123
明文: HELLO
密文: IGOMQ (H+1=I, E+2=G, L+3=O, L+1=M, O+2=Q)
"""

def encrypt(plaintext, key='123'):
    """Gronsfeld加密"""
    if not key:
        return "错误: 请输入数字密钥"
    
    try:
        key_digits = [int(d) for d in key if d.isdigit()]
    except:
        return "错误: 密钥必须是数字"
    
    if not key_digits:
        return "错误: 密钥必须包含数字"
    
    plaintext = ''.join(c.upper() for c in plaintext if c.isalpha())
    
    result = []
    for i, p in enumerate(plaintext):
        p_val = ord(p) - ord('A')
        k_val = key_digits[i % len(key_digits)]
        c_val = (p_val + k_val) % 26
        result.append(chr(c_val + ord('A')))
    
    return ''.join(result)

def decrypt(ciphertext, key='123'):
    """Gronsfeld解密"""
    if not key:
        return "错误: 请输入数字密钥"
    
    try:
        key_digits = [int(d) for d in key if d.isdigit()]
    except:
        return "错误: 密钥必须是数字"
    
    if not key_digits:
        return "错误: 密钥必须包含数字"
    
    ciphertext = ''.join(c.upper() for c in ciphertext if c.isalpha())
    
    result = []
    for i, c in enumerate(ciphertext):
        c_val = ord(c) - ord('A')
        k_val = key_digits[i % len(key_digits)]
        p_val = (c_val - k_val) % 26
        result.append(chr(p_val + ord('A')))
    
    return ''.join(result)
