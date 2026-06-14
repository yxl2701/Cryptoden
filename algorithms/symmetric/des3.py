"""
3DES加密模块
============

【算法介绍】
3DES（Triple DES）是DES的改进版本，通过三次DES运算提高安全性。
它使用两个或三个不同的密钥对数据进行加密。

【加密原理】
3DES使用EDE（Encrypt-Decrypt-Encrypt）模式：
1. 使用K1加密
2. 使用K2解密
3. 使用K3加密

密钥选项：
- 选项1：K1=K2=K3（相当于单DES，不推荐）
- 选项2：K1=K3≠K2（双密钥，112位有效密钥）
- 选项3：K1≠K2≠K3（三密钥，168位有效密钥）

【安全性】
3DES比DES安全得多，但：
- 处理速度较慢
- 正逐步被AES替代
- NIST计划在2023年后禁用
"""

ALGORITHM_NAME = "3DES (Triple DES)"
ALGORITHM_DESC = "3DES对称加密"

PARAMS = []

try:
    from Crypto.Cipher import DES3
    from Crypto.Util.Padding import pad
    from Crypto import Random
    import base64
    DES3_AVAILABLE = True
except ImportError:
    DES3_AVAILABLE = False


def encrypt(plaintext):
    """
    3DES加密函数
    
    使用3DES算法加密数据。
    
    参数:
        plaintext (str): 明文
    
    返回:
        str: 加密结果（Base64编码）
    """
    if not DES3_AVAILABLE:
        return "错误: 未安装pycryptodome库，请运行 pip install pycryptodome"
    
    try:
        key = Random.get_random_bytes(24)
        iv = Random.get_random_bytes(8)
        
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        data = pad(plaintext.encode('utf-8'), 8)
        encrypted = cipher.encrypt(data)
        
        result = base64.b64encode(iv + encrypted).decode()
        result += f"\n\n[密钥(hex)] {key.hex()}"
        result += "\n[密钥长度] 168位（有效）"
        
        return result
    except Exception as e:
        return f"加密错误: {str(e)}"


"""
3DES解密模块
============

【算法介绍】
3DES解密使用相同密钥还原明文数据。
"""

ALGORITHM_NAME = "3DES (Triple DES)"
ALGORITHM_DESC = "3DES对称解密"

PARAMS = [
    {
        'name': 'key',
        'label': '密钥(hex)',
        'type': 'str',
        'default': '',
        'description': '3DES密钥（48个十六进制字符）'
    }
]

try:
    from Crypto.Cipher import DES3
    from Crypto.Util.Padding import unpad
    import base64
    DES3_AVAILABLE = True
except ImportError:
    DES3_AVAILABLE = False


def decrypt(ciphertext, key=''):
    """
    3DES解密函数
    
    使用3DES算法解密数据。
    
    参数:
        ciphertext (str): 密文（Base64编码）
        key (str): 密钥（十六进制）
    
    返回:
        str: 解密结果
    """
    if not DES3_AVAILABLE:
        return "错误: 未安装pycryptodome库"
    
    if not key:
        return "错误: 请提供3DES密钥"
    
    try:
        key_bytes = bytes.fromhex(key)
        data = base64.b64decode(ciphertext)
        
        iv = data[:8]
        encrypted = data[8:]
        
        cipher = DES3.new(key_bytes, DES3.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted), 8)
        
        return decrypted.decode('utf-8')
    except Exception as e:
        return f"解密错误: {str(e)}"
