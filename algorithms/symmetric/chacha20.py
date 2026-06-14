"""
ChaCha20密码
==============
现代流密码，Google推荐用于TLS

【加密原理】
使用256位密钥和96位nonce
基于ChaCha20算法生成密钥流

【特点】
- 密钥长度: 256位
- Nonce长度: 96位
- 非常安全
"""

ALGORITHM_NAME = "ChaCha20密码"
ALGORITHM_DESC = "现代流密码"

try:
    from Crypto.Cipher import ChaCha20
    CHACHA20_AVAILABLE = True
except ImportError:
    CHACHA20_AVAILABLE = False

def encrypt(plaintext, key, nonce=b'000000000000000000000000'):
    """ChaCha20加密"""
    if not CHACHA20_AVAILABLE:
        return "错误: 需要安装 pycryptodome 库\npip install pycryptodome"
    
    if not key:
        return "错误: 请输入密钥"
    
    try:
        key_bytes = key.encode('utf-8')
        if len(key_bytes) != 32:
            return "错误: 密钥必须是32字节(256位)"
        
        if isinstance(nonce, str):
            nonce = nonce.encode('utf-8')
        
        if len(nonce) != 12:
            return "错误: nonce必须是12字节(96位)"
        
        cipher = ChaCha20.new(key=key_bytes, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
        
        return ciphertext.hex()
    except Exception as e:
        return f"错误: {str(e)}"

def decrypt(ciphertext, key, nonce=b'000000000000000000000000'):
    """ChaCha20解密"""
    if not CHACHA20_AVAILABLE:
        return "错误: 需要安装 pycryptodome 库\npip install pycryptodome"
    
    if not key:
        return "错误: 请输入密钥"
    
    try:
        key_bytes = key.encode('utf-8')
        if len(key_bytes) != 32:
            return "错误: 密钥必须是32字节(256位)"
        
        if isinstance(nonce, str):
            nonce = nonce.encode('utf-8')
        
        if len(nonce) != 12:
            return "错误: nonce必须是12字节(96位)"
        
        cipher = ChaCha20.new(key=key_bytes, nonce=nonce)
        ciphertext_bytes = bytes.fromhex(ciphertext)
        plaintext = cipher.decrypt(ciphertext_bytes)
        
        return plaintext.decode('utf-8')
    except Exception as e:
        return f"错误: {str(e)}"


"""
ChaCha20密码解密模块
"""

ALGORITHM_NAME = "ChaCha20密码"
ALGORITHM_DESC = "现代流密码"

try:
    from Crypto.Cipher import ChaCha20
    CHACHA20_AVAILABLE = True
except ImportError:
    CHACHA20_AVAILABLE = False

def decrypt(ciphertext, key, nonce=b'000000000000000000000000'):
    """ChaCha20解密"""
    if not CHACHA20_AVAILABLE:
        return "错误: 需要安装 pycryptodome 库\npip install pycryptodome"
    
    if not key:
        return "错误: 请输入密钥"
    
    try:
        key_bytes = key.encode('utf-8')
        if len(key_bytes) != 32:
            return "错误: 密钥必须是32字节(256位)"
        
        if isinstance(nonce, str):
            nonce = nonce.encode('utf-8')
        
        if len(nonce) != 12:
            return "错误: nonce必须是12字节(96位)"
        
        cipher = ChaCha20.new(key=key_bytes, nonce=nonce)
        ciphertext_bytes = bytes.fromhex(ciphertext)
        plaintext = cipher.decrypt(ciphertext_bytes)
        
        return plaintext.decode('utf-8')
    except Exception as e:
        return f"错误: {str(e)}"
