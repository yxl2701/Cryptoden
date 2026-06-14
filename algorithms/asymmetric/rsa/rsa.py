"""
RSA加密模块
===========

【算法介绍】
RSA是一种非对称加密算法，由Ron Rivest、Adi Shamir和Leonard Adleman
于1977年提出。RSA是目前最广泛使用的非对称加密算法之一。

【加密原理】
RSA基于大整数分解难题：
1. 选择两个大素数p和q
2. 计算n = p × q（模数）
3. 计算欧拉函数φ(n) = (p-1)(q-1)
4. 选择公钥指数e，满足1 < e < φ(n)且gcd(e, φ(n)) = 1
5. 计算私钥d，满足e × d ≡ 1 (mod φ(n))

加密：c = m^e mod n
解密：m = c^d mod n

【密钥长度】
推荐使用2048位或更长的密钥：
- 1024位：已不安全
- 2048位：当前标准
- 4096位：高安全需求

【应用场景】
1. 数字签名
2. 密钥交换
3. 数据加密
4. SSL/TLS证书
"""

ALGORITHM_NAME = "rsa"
ALGORITHM_DESC = "RSA非对称加密"

try:
    from algorithms.asymmetric.rsa.utils import format_value, decode_plaintext
except ImportError:
    from .utils import format_value, decode_plaintext

PARAMS = [
    {
        'name': 'key_size',
        'label': '密钥长度',
        'type': 'choice',
        'default': '2048',
        'choices': ['1024', '2048', '3072', '4096'],
        'description': 'RSA密钥长度（位）'
    }
]

try:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    RSA_AVAILABLE = True
except ImportError:
    RSA_AVAILABLE = False


def _clean_base64(text):
    cleaned = ''.join(text.split())
    if not cleaned:
        return ''
    return cleaned + ('=' * ((-len(cleaned)) % 4))


def _extract_section(text, title):
    marker = f"[{title}]"
    start = text.find(marker)
    if start < 0:
        return ''
    start += len(marker)
    next_marker = text.find('\n[', start)
    if next_marker < 0:
        return text[start:].strip()
    return text[start:next_marker].strip()


def _extract_ciphertext(text):
    marker = text.find('\n[')
    return text[:marker].strip() if marker >= 0 else text.strip()


def _import_public_key(public_key):
    if not public_key:
        return None
    key = RSA.import_key(public_key)
    if key.has_private():
        return key.publickey()
    return key


def _product(values):
    result = 1
    for value in values:
        result *= value
    return result


def derive_parameters(p=None, q=None, e=None, c=None, n=None, d=None, output_format='decimal'):
    """根据常见RSA已知量推导n、phi、d、m等辅助参数。"""
    try:
        values = {'p': p, 'q': q, 'e': e, 'c': c, 'n': n, 'd': d}
        p, q, e, c, n, d = (int(values[name]) if values[name] is not None else None for name in values)

        if n is None and p and q:
            n = p * q

        if q is None and n and p and n % p == 0:
            q = n // p
        if p is None and n and q and n % q == 0:
            p = n // q

        phi = None
        lambda_n = None
        if p and q:
            phi = (p - 1) * (q - 1)
            import math
            lambda_n = phi // math.gcd(p - 1, q - 1)

        if d is None and e and phi:
            try:
                d = pow(e, -1, phi)
            except ValueError:
                d = None

        m = None
        m_crt = None
        if c is not None and n and d:
            m = pow(c, d, n)
            if p and q:
                dp = d % (p - 1)
                dq = d % (q - 1)
                q_inv = pow(q, -1, p)
                m1 = pow(c, dp, p)
                m2 = pow(c, dq, q)
                m_crt = (m2 + q * ((q_inv * (m1 - m2)) % p)) % n

        result = {
            'success': True,
            'p': p,
            'q': q,
            'n': n,
            'e': e,
            'd': d,
            'phi': phi,
            'lambda_n': lambda_n,
            'c': c,
            'm': m,
            'm_crt': m_crt,
        }
        result['text'] = format_derived_parameters(result, output_format)
        return result
    except Exception as ex:
        return {'success': False, 'error': str(ex), 'text': f"RSA参数推导错误: {str(ex)}"}


def format_derived_parameters(result, output_format='decimal'):
    """格式化RSA参数推导结果，方便GUI和测试复用。"""
    if not result.get('success'):
        return result.get('text') or result.get('error', '')

    labels = [
        ('p', 'p'),
        ('q', 'q'),
        ('n', 'n = p * q'),
        ('phi', 'phi(n) = (p - 1) * (q - 1)'),
        ('lambda_n', 'lambda(n) = lcm(p - 1, q - 1)'),
        ('e', 'e'),
        ('d', 'd = e^-1 mod phi(n)'),
        ('c', 'c'),
        ('m', 'm = c^d mod n'),
    ]
    lines = []
    for key, label in labels:
        value = result.get(key)
        if value is not None:
            lines.append(f"{label}: {format_value(value, output_format)}")

    if result.get('m_crt') is not None:
        lines.append(f"m(CRT加速校验): {format_value(result['m_crt'], output_format)}")

    if result.get('m') is not None:
        lines.append(f"明文(UTF-8尝试): {decode_plaintext(result['m'])}")

    if not lines:
        return "未能推导出新参数，请至少提供 p/q、n/p、p/q/e 或 p/q/e/c 等组合。"
    return "\n".join(lines)


def encrypt(plaintext, key_size='2048', public_key=''):
    """
    RSA加密函数
    
    使用RSA公钥加密数据。
    
    参数:
        plaintext (str): 明文
        key_size (str): 密钥长度
    
    返回:
        str: 加密结果（Base64编码）
    """
    if not RSA_AVAILABLE:
        return "错误: 未安装pycryptodome库，请运行 pip install pycryptodome"
    
    try:
        import base64
        
        generated_key = None
        if public_key:
            key = _import_public_key(public_key)
            if key is None:
                return "错误: 公钥为空"
        else:
            key_size_int = int(key_size)
            generated_key = RSA.generate(key_size_int)
            key = generated_key.publickey()

        cipher = PKCS1_OAEP.new(key)
        
        data = plaintext.encode('utf-8')
        
        max_size = (key.size_in_bytes()) - 42
        if len(data) > max_size:
            return f"错误: 数据过长，最大支持{max_size}字节"
        
        encrypted = cipher.encrypt(data)
        
        result = base64.b64encode(encrypted).decode()
        result += "\n\n[公钥]\n"
        result += key.export_key().decode()
        if generated_key:
            result += "\n\n[私钥]\n"
            result += generated_key.export_key().decode()
        
        return result
    except Exception as e:
        return f"加密错误: {str(e)}"


"""
RSA解密模块
===========

【算法介绍】
RSA解密使用私钥还原明文数据。
"""

ALGORITHM_NAME = "rsa"
ALGORITHM_DESC = "RSA非对称解密"

PARAMS = [
    {
        'name': 'private_key',
        'label': '私钥',
        'type': 'str',
        'default': '',
        'description': 'RSA私钥（PEM格式）'
    }
]

try:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    RSA_AVAILABLE = True
except ImportError:
    RSA_AVAILABLE = False


def decrypt(ciphertext, private_key=''):
    """
    RSA解密函数
    
    使用RSA私钥解密数据。
    
    参数:
        ciphertext (str): 密文（Base64编码）
        private_key (str): RSA私钥
    
    返回:
        str: 解密结果
    """
    if not RSA_AVAILABLE:
        return "错误: 未安装pycryptodome库"
    
    try:
        import base64

        if not private_key:
            private_key = _extract_section(ciphertext, '私钥')
        if not private_key:
            return "错误: 请提供RSA私钥"
        
        key = RSA.import_key(private_key)
        if not key.has_private():
            return "错误: 提供的密钥不是私钥"
        cipher = PKCS1_OAEP.new(key)
        
        encrypted = base64.b64decode(_clean_base64(_extract_ciphertext(ciphertext)), validate=True)
        decrypted = cipher.decrypt(encrypted)
        
        return decrypted.decode('utf-8')
    except Exception as e:
        return f"解密错误: {str(e)}"
