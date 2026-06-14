"""
DES加密模块
===========

【算法介绍】
DES（Data Encryption Standard）是一种对称加密算法，
由IBM于1970年代开发，1977年被美国国家标准局采纳为标准。

【加密原理】
DES是一种分组密码：
1. 密钥长度：56位（实际64位，8位用于奇偶校验）
2. 分组大小：64位（8字节）
3. 加密轮数：16轮Feistel结构

【安全性警告】
DES已不再安全：
- 56位密钥太短，可被暴力破解
- 1998年，EFF用专用设备22小时破解DES
- 推荐使用AES或3DES替代

【应用场景】
仅用于学习或兼容旧系统，不推荐用于新系统。
"""

ALGORITHM_NAME = "des"
ALGORITHM_DESC = "DES对称加密（已不安全）"

PARAMS = []

try:
    from Crypto.Cipher import DES
    from Crypto.Util.Padding import pad
    from Crypto import Random
    import base64
    DES_AVAILABLE = True
except ImportError:
    DES_AVAILABLE = False


def encrypt(plaintext):
    """
    DES加密函数
    
    使用DES算法加密数据。
    
    参数:
        plaintext (str): 明文
    
    返回:
        str: 加密结果（Base64编码）
    """
    if not DES_AVAILABLE:
        return "错误: 未安装pycryptodome库，请运行 pip install pycryptodome"
    
    try:
        key = Random.get_random_bytes(8)
        iv = Random.get_random_bytes(8)
        
        cipher = DES.new(key, DES.MODE_CBC, iv)
        data = pad(plaintext.encode('utf-8'), 8)
        encrypted = cipher.encrypt(data)
        
        result = base64.b64encode(iv + encrypted).decode()
        result += f"\n\n[密钥(hex)] {key.hex()}"
        result += "\n\n[警告] DES已不安全，推荐使用AES"
        
        return result
    except Exception as e:
        return f"加密错误: {str(e)}"


"""
DES解密模块
===========

【算法介绍】
DES解密使用相同密钥还原明文数据。
"""

ALGORITHM_NAME = "des"
ALGORITHM_DESC = "DES对称解密"

PARAMS = [
    {
        'name': 'key',
        'label': '密钥(hex)',
        'type': 'str',
        'default': '',
        'description': 'DES密钥（16个十六进制字符）'
    }
]

try:
    from Crypto.Cipher import DES
    from Crypto.Util.Padding import unpad
    import base64
    DES_AVAILABLE = True
except ImportError:
    DES_AVAILABLE = False


def decrypt(ciphertext, key=''):
    """
    DES解密函数
    
    使用DES算法解密数据。
    
    参数:
        ciphertext (str): 密文（Base64编码）
        key (str): 密钥（十六进制）
    
    返回:
        str: 解密结果
    """
    if not DES_AVAILABLE:
        return "错误: 未安装pycryptodome库"
    
    if not key:
        return "错误: 请提供DES密钥"
    
    try:
        key_bytes = bytes.fromhex(key)
        data = base64.b64decode(ciphertext)
        
        iv = data[:8]
        encrypted = data[8:]
        
        cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted), 8)
        
        return decrypted.decode('utf-8')
    except Exception as e:
        return f"解密错误: {str(e)}"
