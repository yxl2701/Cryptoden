"""
XOR密码
=======
最简单的对称加密，按位异或

【加密原理】
明文与密钥逐字节异或
加密和解密操作相同

【特点】
- 简单快速
- 不安全，仅用于教学
"""

ALGORITHM_NAME = "XOR密码"
ALGORITHM_DESC = "简单异或密码"

def encrypt(plaintext, key):
    """XOR加密"""
    if not key:
        return "错误: 请输入密钥"
    
    key_bytes = key.encode('utf-8')
    plaintext_bytes = plaintext.encode('utf-8')
    
    result = []
    for i, byte in enumerate(plaintext_bytes):
        result.append(byte ^ key_bytes[i % len(key_bytes)])
    
    return bytes(result).hex()

def decrypt(ciphertext, key):
    """XOR解密（与加密相同）"""
    if not key:
        return "错误: 请输入密钥"
    
    try:
        ciphertext_bytes = bytes.fromhex(ciphertext)
    except:
        return "错误: 密文格式错误"
    
    key_bytes = key.encode('utf-8')
    
    result = []
    for i, byte in enumerate(ciphertext_bytes):
        result.append(byte ^ key_bytes[i % len(key_bytes)])
    
    return bytes(result).decode('utf-8', errors='replace')


"""
XOR密码解密模块
"""

ALGORITHM_NAME = "XOR密码"
ALGORITHM_DESC = "简单异或密码"

def decrypt(ciphertext, key):
    """XOR解密"""
    if not key:
        return "错误: 请输入密钥"
    
    try:
        ciphertext_bytes = bytes.fromhex(ciphertext)
    except:
        return "错误: 密文格式错误"
    
    key_bytes = key.encode('utf-8')
    
    result = []
    for i, byte in enumerate(ciphertext_bytes):
        result.append(byte ^ key_bytes[i % len(key_bytes)])
    
    return bytes(result).decode('utf-8', errors='replace')
