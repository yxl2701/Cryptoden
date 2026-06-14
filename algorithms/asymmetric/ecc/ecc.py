"""
ECC加密模块
===========

【算法介绍】
ECC（椭圆曲线密码学）是一种基于椭圆曲线数学的非对称加密算法。
相比RSA，ECC可以用更短的密钥达到相同的安全强度。

【加密原理】
ECC基于椭圆曲线离散对数问题（ECDLP）：
1. 选择一条椭圆曲线和基点G
2. 私钥d是随机整数
3. 公钥Q = d × G
4. 加密使用ECIES方案

【密钥长度对比】
- ECC 256位 ≈ RSA 3072位
- ECC 384位 ≈ RSA 7680位
- ECC 521位 ≈ RSA 15360位

【常用曲线】
- P-256 (secp256r1)
- P-384 (secp384r1)
- P-521 (secp521r1)
- secp256k1（比特币使用）
"""

ALGORITHM_NAME = "ecc"
ALGORITHM_DESC = "ECC椭圆曲线加密"

PARAMS = [
    {
        'name': 'curve',
        'label': '曲线',
        'type': 'choice',
        'default': 'P-256',
        'choices': ['P-256', 'P-384', 'P-521', 'secp256k1'],
        'description': '椭圆曲线类型'
    }
]

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    ECC_AVAILABLE = True
except ImportError:
    ECC_AVAILABLE = False


def encrypt(plaintext, curve='P-256'):
    """
    ECC加密函数
    
    使用ECIES方案加密数据。
    
    参数:
        plaintext (str): 明文
        curve (str): 椭圆曲线类型
    
    返回:
        str: 加密结果
    """
    if not ECC_AVAILABLE:
        return "错误: 未安装cryptography库，请运行 pip install cryptography"
    
    try:
        curve_map = {
            'P-256': ec.SECP256R1(),
            'P-384': ec.SECP384R1(),
            'P-521': ec.SECP521R1(),
            'secp256k1': ec.SECP256K1(),
        }
        
        private_key = ec.generate_private_key(curve_map[curve], default_backend())
        public_key = private_key.public_key()
        
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        import os
        import base64
        
        ephemeral_key = ec.generate_private_key(curve_map[curve], default_backend())
        shared_key = ephemeral_key.exchange(ec.ECDH(), public_key)
        
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ecies',
            backend=default_backend()
        ).derive(shared_key)
        
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(derived_key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        
        ephemeral_public = ephemeral_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        
        result = base64.b64encode(ephemeral_public + iv + ciphertext).decode()
        result += "\n\n[私钥]\n"
        result += private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        return result
    except Exception as e:
        return f"加密错误: {str(e)}"


"""
ECC解密模块
===========

【算法介绍】
ECC解密使用私钥还原明文数据。
"""

ALGORITHM_NAME = "ecc"
ALGORITHM_DESC = "ECC椭圆曲线解密"

PARAMS = [
    {
        'name': 'private_key',
        'label': '私钥',
        'type': 'str',
        'default': '',
        'description': 'ECC私钥（PEM格式）'
    }
]

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    ECC_AVAILABLE = True
except ImportError:
    ECC_AVAILABLE = False


def _curve_from_name(curve='P-256'):
    curve_map = {
        'P-256': ec.SECP256R1(),
        'SECP256R1': ec.SECP256R1(),
        'P-384': ec.SECP384R1(),
        'SECP384R1': ec.SECP384R1(),
        'P-521': ec.SECP521R1(),
        'SECP521R1': ec.SECP521R1(),
        'secp256k1': ec.SECP256K1(),
        'SECP256K1': ec.SECP256K1(),
    }
    key = str(curve).strip()
    return curve_map.get(key, ec.SECP256R1())


def _hash_from_name(hash_algorithm='SHA256'):
    name = str(hash_algorithm).replace('-', '').replace('_', '').upper()
    hash_map = {
        'SHA1': hashes.SHA1,
        'SHA224': hashes.SHA224,
        'SHA256': hashes.SHA256,
        'SHA384': hashes.SHA384,
        'SHA512': hashes.SHA512,
    }
    return hash_map.get(name, hashes.SHA256)()


def _extract_section(text, title):
    marker = f'[{title}]'
    if marker not in text:
        return ''
    after = text.split(marker, 1)[1]
    next_marker = after.find('\n[')
    if next_marker >= 0:
        after = after[:next_marker]
    return after.strip()


def generate_key_pair(curve='P-256'):
    if not ECC_AVAILABLE:
        return "错误: 未安装cryptography库"
    try:
        private_key = ec.generate_private_key(_curve_from_name(curve), default_backend())
        public_key = private_key.public_key()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        return f"[公钥]\n{public_pem}\n[私钥]\n{private_pem}"
    except Exception as e:
        return f"生成密钥错误: {str(e)}"


def sign(message, private_key='', curve='P-256', hash_algorithm='SHA256', output_format='base64'):
    if not ECC_AVAILABLE:
        return "错误: 未安装cryptography库"
    try:
        if private_key:
            private_key_text = _extract_section(private_key, '私钥') or private_key.strip()
            key = serialization.load_pem_private_key(
                private_key_text.encode(), password=None, backend=default_backend()
            )
        else:
            key = ec.generate_private_key(_curve_from_name(curve), default_backend())

        signature = key.sign(message.encode('utf-8'), ec.ECDSA(_hash_from_name(hash_algorithm)))
        if str(output_format).lower() == 'rs':
            r, s = decode_dss_signature(signature)
            signature_text = f"r={r}\ns={s}"
        else:
            import base64
            signature_text = base64.b64encode(signature).decode('ascii')
        public_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        result = f"[签名]\n{signature_text}\n[公钥]\n{public_pem}"
        if not private_key:
            private_pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
            result += f"[私钥]\n{private_pem}"
        return result
    except Exception as e:
        return f"签名错误: {str(e)}"


def verify(message, signature, public_key='', hash_algorithm='SHA256'):
    if not ECC_AVAILABLE:
        return "错误: 未安装cryptography库"
    if not public_key:
        public_key = _extract_section(signature, '公钥')
    signature_text = _extract_section(signature, '签名') or signature.strip()
    if not public_key:
        return "验签失败: 请提供ECC公钥"
    try:
        import base64
        key = serialization.load_pem_public_key(public_key.encode(), backend=default_backend())
        if 'r=' in signature_text and 's=' in signature_text:
            values = {}
            for line in signature_text.splitlines():
                if '=' in line:
                    k, v = line.split('=', 1)
                    values[k.strip()] = int(v.strip(), 0)
            signature_bytes = encode_dss_signature(values['r'], values['s'])
        else:
            signature_bytes = base64.b64decode(''.join(signature_text.split()))
        key.verify(signature_bytes, message.encode('utf-8'), ec.ECDSA(_hash_from_name(hash_algorithm)))
        return "验签成功"
    except Exception as e:
        return f"验签失败: {str(e)}"


def decrypt(ciphertext, private_key=''):
    """
    ECC解密函数
    
    使用ECIES方案解密数据。
    
    参数:
        ciphertext (str): 密文
        private_key (str): ECC私钥
    
    返回:
        str: 解密结果
    """
    if not ECC_AVAILABLE:
        return "错误: 未安装cryptography库"
    
    if not private_key:
        return "错误: 请提供ECC私钥"
    
    try:
        import base64
        
        priv_key = serialization.load_pem_private_key(
            private_key.encode(),
            password=None,
            backend=default_backend()
        )
        
        data = base64.b64decode(ciphertext)
        
        curve_size = {
            ec.SECP256R1: 32,
            ec.SECP384R1: 48,
            ec.SECP521R1: 66,
            ec.SECP256K1: 32,
        }
        
        curve_type = type(priv_key.public_key().curve)
        point_size = curve_size.get(curve_type, 32)
        
        ephemeral_public_bytes = data[:point_size * 2 + 1]
        iv = data[point_size * 2 + 1:point_size * 2 + 17]
        encrypted = data[point_size * 2 + 17:]
        
        ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
            priv_key.public_key().curve,
            ephemeral_public_bytes
        )
        
        shared_key = priv_key.exchange(ec.ECDH(), ephemeral_public)
        
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ecies',
            backend=default_backend()
        ).derive(shared_key)
        
        cipher = Cipher(algorithms.AES(derived_key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(encrypted) + decryptor.finalize()
        
        return plaintext.decode('utf-8')
    except Exception as e:
        return f"解密错误: {str(e)}"
