"""
RC4密码
=========
一种流密码，密钥长度1-256字节

【加密原理】
基于RC4算法的流密码
使用密钥生成伪随机字节流，与明文异或

【特点】
- 密钥长度: 1-256字节
- 速度快，但不安全
"""

ALGORITHM_NAME = "RC4密码"
ALGORITHM_DESC = "流密码"

def encrypt(plaintext, key):
    """RC4加密"""
    if not key:
        return "错误: 请输入密钥"
    
    key_bytes = key.encode('utf-8')
    plaintext_bytes = plaintext.encode('utf-8')
    
    S = list(range(256))
    j = 0
    
    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
        S[i], S[j] = S[j], S[i]
    
    i = j = 0
    result = []
    
    for byte in plaintext_bytes:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        result.append(k ^ byte)
    
    return bytes(result).hex()

def decrypt(ciphertext, key):
    """RC4解密（与加密相同）"""
    return encrypt(ciphertext, key)


"""
RC4密码解密模块
"""

ALGORITHM_NAME = "RC4密码"
ALGORITHM_DESC = "流密码"

def decrypt(ciphertext, key):
    """RC4解密（与加密相同）"""
    if not key:
        return "错误: 请输入密钥"
    
    key_bytes = key.encode('utf-8')
    
    try:
        ciphertext_bytes = bytes.fromhex(ciphertext)
    except:
        return "错误: 密文格式错误"
    
    S = list(range(256))
    j = 0
    
    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
        S[i], S[j] = S[j], S[i]
    
    i = j = 0
    result = []
    
    for byte in ciphertext_bytes:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        result.append(k ^ byte)
    
    return bytes(result).decode('utf-8', errors='replace')
