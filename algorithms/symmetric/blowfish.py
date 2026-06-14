"""
Blowfish密码
==============
一种对称密钥分组密码，块大小64位，密钥长度32-448位

【加密原理】
Feistel网络结构，16轮加密
每轮使用密钥相关子密钥

【特点】
- 块大小: 64位
- 密钥长度: 32-448位
- 轮数: 16轮
"""

ALGORITHM_NAME = "Blowfish密码"
ALGORITHM_DESC = "对称密钥分组密码"

try:
    from Crypto.Cipher import Blowfish
    from Crypto.Util.Padding import pad, unpad
    BLOWFISH_AVAILABLE = True
except ImportError:
    BLOWFISH_AVAILABLE = False

def encrypt(plaintext, key, mode='ECB'):
    """Blowfish加密"""
    if not BLOWFISH_AVAILABLE:
        return "错误: 需要安装 pycryptodome 库\npip install pycryptodome"
    
    if not key:
        return "错误: 请输入密钥"
    
    try:
        key_bytes = key.encode('utf-8')
        cipher = Blowfish.new(key_bytes, mode)
        
        plaintext_bytes = plaintext.encode('utf-8')
        padded = pad(plaintext_bytes, Blowfish.block_size)
        encrypted = cipher.encrypt(padded)
        
        return encrypted.hex()
    except Exception as e:
        return f"错误: {str(e)}"

def decrypt(ciphertext, key, mode='ECB'):
    """Blowfish解密"""
    if not BLOWFISH_AVAILABLE:
        return "错误: 需要安装 pycryptodome 库\npip install pycryptodome"
    
    if not key:
        return "错误: 请输入密钥"
    
    try:
        key_bytes = key.encode('utf-8')
        cipher = Blowfish.new(key_bytes, mode)
        
        ciphertext_bytes = bytes.fromhex(ciphertext)
        decrypted = cipher.decrypt(ciphertext_bytes)
        unpadded = unpad(decrypted, Blowfish.block_size)
        
        return unpadded.decode('utf-8')
    except Exception as e:
        return f"错误: {str(e)}"


"""
Blowfish密码解密模块
"""

ALGORITHM_NAME = "Blowfish密码"
ALGORITHM_DESC = "对称密钥分组密码"

try:
    from Crypto.Cipher import Blowfish
    from Crypto.Util.Padding import unpad
    BLOWFISH_AVAILABLE = True
except ImportError:
    BLOWFISH_AVAILABLE = False

def decrypt(ciphertext, key, mode='ECB'):
    """Blowfish解密"""
    if not BLOWFISH_AVAILABLE:
        return "错误: 需要安装 pycryptodome 库\npip install pycryptodome"
    
    if not key:
        return "错误: 请输入密钥"
    
    try:
        key_bytes = key.encode('utf-8')
        cipher = Blowfish.new(key_bytes, mode)
        
        ciphertext_bytes = bytes.fromhex(ciphertext)
        decrypted = cipher.decrypt(ciphertext_bytes)
        unpadded = unpad(decrypted, Blowfish.block_size)
        
        return unpadded.decode('utf-8')
    except Exception as e:
        return f"错误: {str(e)}"
