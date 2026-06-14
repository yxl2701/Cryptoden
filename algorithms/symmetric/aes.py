"""
AES加密模块
===========

【算法介绍】
AES（Advanced Encryption Standard）是一种对称加密算法，
由比利时密码学家Joan Daemen和Vincent Rijmen设计，
于2001年被美国国家标准与技术研究院（NIST）选为加密标准。

【加密原理】
AES是一种分组密码，将数据分成128位（16字节）的块进行加密：
1. 密钥长度：128/192/256位
2. 分组大小：固定128位
3. 加密轮数：10/12/14轮（取决于密钥长度）

【工作模式】
- ECB：电子密码本模式（不推荐）
- CBC：密码分组链接模式（需要IV）
- CTR：计数器模式（流密码模式）
- GCM：伽罗瓦/计数器模式（认证加密）

【安全性】
AES是目前最安全的对称加密算法之一：
- 无已知有效攻击
- 256位密钥可抵抗量子计算机攻击
- 广泛应用于政府、金融等领域
"""

ALGORITHM_NAME = "aes"
ALGORITHM_DESC = "AES对称加密"

PARAMS = [
    {
        'name': 'key_size',
        'label': '密钥长度',
        'type': 'choice',
        'default': '256',
        'choices': ['128', '192', '256'],
        'description': 'AES密钥长度（位）'
    },
    {
        'name': 'mode',
        'label': '工作模式',
        'type': 'choice',
        'default': 'CBC',
        'choices': ['ECB', 'CBC', 'CTR'],
        'description': 'AES工作模式'
    }
]

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    from Crypto import Random
    import base64
    AES_AVAILABLE = True
except ImportError:
    AES_AVAILABLE = False


def encrypt(plaintext, key_size='256', mode='CBC'):
    """
    AES加密函数
    
    使用AES算法加密数据。
    
    参数:
        plaintext (str): 明文
        key_size (str): 密钥长度（位）
        mode (str): 工作模式
    
    返回:
        str: 加密结果（Base64编码）
    """
    if not AES_AVAILABLE:
        return "错误: 未安装pycryptodome库，请运行 pip install pycryptodome"
    
    try:
        key_bytes = int(key_size) // 8
        key = Random.get_random_bytes(key_bytes)
        
        if mode == 'ECB':
            cipher = AES.new(key, AES.MODE_ECB)
            data = pad(plaintext.encode('utf-8'), 16)
            encrypted = cipher.encrypt(data)
            result = base64.b64encode(encrypted).decode()
        elif mode == 'CBC':
            iv = Random.get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            data = pad(plaintext.encode('utf-8'), 16)
            encrypted = cipher.encrypt(data)
            result = base64.b64encode(iv + encrypted).decode()
        else:
            nonce = Random.get_random_bytes(8)
            cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
            encrypted = cipher.encrypt(plaintext.encode('utf-8'))
            result = base64.b64encode(nonce + encrypted).decode()
        
        result += f"\n\n[密钥(hex)] {key.hex()}"
        result += f"\n[密钥长度] {key_size}位"
        result += f"\n[工作模式] {mode}"
        
        return result
    except Exception as e:
        return f"加密错误: {str(e)}"


"""
AES解密模块
===========

【算法介绍】
AES解密使用相同密钥还原明文数据。
"""

ALGORITHM_NAME = "aes"
ALGORITHM_DESC = "AES对称解密"

PARAMS = [
    {
        'name': 'key',
        'label': '密钥(hex)',
        'type': 'str',
        'default': '',
        'description': 'AES密钥（十六进制）'
    },
    {
        'name': 'mode',
        'label': '工作模式',
        'type': 'choice',
        'default': 'CBC',
        'choices': ['ECB', 'CBC', 'CTR'],
        'description': 'AES工作模式'
    }
]

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    import base64
    AES_AVAILABLE = True
except ImportError:
    AES_AVAILABLE = False


def decrypt(ciphertext, key='', mode='CBC'):
    """
    AES解密函数
    
    使用AES算法解密数据。
    
    参数:
        ciphertext (str): 密文（Base64编码）
        key (str): 密钥（十六进制）
        mode (str): 工作模式
    
    返回:
        str: 解密结果
    """
    if not AES_AVAILABLE:
        return "错误: 未安装pycryptodome库"
    
    if not key:
        return "错误: 请提供AES密钥"
    
    try:
        key_bytes = bytes.fromhex(key)
        data = base64.b64decode(ciphertext)
        
        if mode == 'ECB':
            cipher = AES.new(key_bytes, AES.MODE_ECB)
            decrypted = unpad(cipher.decrypt(data), 16)
        elif mode == 'CBC':
            iv = data[:16]
            encrypted = data[16:]
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(encrypted), 16)
        else:
            nonce = data[:8]
            encrypted = data[8:]
            cipher = AES.new(key_bytes, AES.MODE_CTR, nonce=nonce)
            decrypted = cipher.decrypt(encrypted)
        
        return decrypted.decode('utf-8')
    except Exception as e:
        return f"解密错误: {str(e)}"
