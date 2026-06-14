"""
Fernet密码 (AES-128-CBC + HMAC)
================================
Python cryptography库的高级对称加密

【加密原理】
使用AES-128-CBC加密
使用HMAC-SHA256进行认证

【特点】
- 自动处理IV和填充
- 提供完整性验证
- 非常安全
"""

ALGORITHM_NAME = "Fernet密码"
ALGORITHM_DESC = "AES-128-CBC + HMAC认证加密"

try:
    from cryptography.fernet import Fernet
    import base64
    FERNET_AVAILABLE = True
except ImportError:
    FERNET_AVAILABLE = False

def generate_key():
    """生成Fernet密钥"""
    if FERNET_AVAILABLE:
        return Fernet.generate_key().decode('utf-8')
    return None

def encrypt(plaintext, key=None):
    """Fernet加密"""
    if not FERNET_AVAILABLE:
        return "错误: 需要安装 cryptography 库\npip install cryptography"
    
    try:
        if key is None:
            key = Fernet.generate_key()
        elif isinstance(key, str):
            key = key.encode('utf-8')
        
        f = Fernet(key)
        ciphertext = f.encrypt(plaintext.encode('utf-8'))
        
        return {
            'ciphertext': ciphertext.decode('utf-8'),
            'key': key.decode('utf-8') if isinstance(key, bytes) else key
        }
    except Exception as e:
        return f"错误: {str(e)}"

def decrypt(ciphertext, key):
    """Fernet解密"""
    if not FERNET_AVAILABLE:
        return "错误: 需要安装 cryptography 库\npip install cryptography"
    
    try:
        if isinstance(key, str):
            key = key.encode('utf-8')
        
        f = Fernet(key)
        
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode('utf-8')
        
        plaintext = f.decrypt(ciphertext)
        return plaintext.decode('utf-8')
    except Exception as e:
        return f"错误: {str(e)}"


"""
Fernet密码解密模块
"""

ALGORITHM_NAME = "Fernet密码"
ALGORITHM_DESC = "AES-128-CBC + HMAC认证加密"

try:
    from cryptography.fernet import Fernet
    FERNET_AVAILABLE = True
except ImportError:
    FERNET_AVAILABLE = False

def decrypt(ciphertext, key):
    """Fernet解密"""
    if not FERNET_AVAILABLE:
        return "错误: 需要安装 cryptography 库\npip install cryptography"
    
    try:
        if isinstance(key, str):
            key = key.encode('utf-8')
        
        f = Fernet(key)
        
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode('utf-8')
        
        plaintext = f.decrypt(ciphertext)
        return plaintext.decode('utf-8')
    except Exception as e:
        return f"错误: {str(e)}"
