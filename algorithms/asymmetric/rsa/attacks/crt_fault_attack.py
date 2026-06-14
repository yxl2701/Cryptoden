"""
CRT故障攻击模块
===============

【攻击原理】
在RSA-CRT签名计算中，如果计算过程中发生故障，可能导致签名错误。
通过比较正确签名和错误签名，可以分解模数n。

RSA-CRT签名:
- s_p = m^d_p mod p
- s_q = m^d_q mod q
- s = CRT(s_p, s_q) mod n

如果在计算s_p时发生故障（得到错误的s_p'），则:
- s' = CRT(s_p', s_q) mod n
- s'^e ≡ m (mod q)，但 s'^e ≢ m (mod p)
- 因此 gcd(s'^e - m, n) = q

【适用条件】
1. 已知正确签名和错误签名
2. 或者已知消息和错误签名

【CTF例题】
已知: n, e, 消息m, 错误签名s'
求: p, q

【参考】
- Bellcore攻击
- CRT故障攻击
"""

ATTACK_NAME = "CRT故障攻击"
ATTACK_DESC = "利用错误签名恢复因子"
ATTACK_HINT = """【攻击说明】
利用RSA-CRT计算中的故障来分解模数。

输入参数:
- 模数n: RSA模数
- 公钥e: RSA公钥
- 消息m: 原始消息（可选，如果有正确签名）
- 正确签名sv: 有效的签名（可选）
- 错误签名sf: 故障产生的签名

两种模式:
1. 已知消息和错误签名
2. 已知正确签名和错误签名"""

INPUT_FIELDS = [
    {
        'name': 'n',
        'label': '模数 n',
        'type': 'text',
        'default': '',
        'placeholder': '输入模数n',
        'required': True
    },
    {
        'name': 'e',
        'label': '公钥 e',
        'type': 'text',
        'default': '65537',
        'placeholder': '输入公钥e',
        'required': True
    },
    {
        'name': 'm',
        'label': '消息 m (可选)',
        'type': 'text',
        'default': '',
        'placeholder': '输入原始消息',
        'required': False
    },
    {
        'name': 'sv',
        'label': '正确签名 (可选)',
        'type': 'text',
        'default': '',
        'placeholder': '输入正确签名',
        'required': False
    },
    {
        'name': 'sf',
        'label': '错误签名',
        'type': 'text',
        'default': '',
        'placeholder': '输入错误签名',
        'required': True
    }
]

import math


def attack_known_message(n, e, m, sf):
    """
    已知消息和错误签名时恢复因子
    
    参数:
        n: 模数
        e: 公钥
        m: 原始消息
        sf: 错误签名
    
    返回:
        tuple: (p, q) 或 None
    """
    g = math.gcd(m - pow(sf, e, n), n)
    if g > 1 and g < n:
        return g, n // g
    return None


def attack_known_valid_signature(n, e, sv, sf):
    """
    已知正确签名和错误签名时恢复因子
    
    参数:
        n: 模数
        e: 公钥
        sv: 正确签名
        sf: 错误签名
    
    返回:
        tuple: (p, q) 或 None
    """
    if sv == sf:
        return None
    
    g = math.gcd(sv - sf, n)
    if g > 1 and g < n:
        return g, n // g
    return None


def attack(n, e, m='', sv='', sf=''):
    """
    执行CRT故障攻击
    
    参数:
        n: 模数
        e: 公钥
        m: 原始消息（可选）
        sv: 正确签名（可选）
        sf: 错误签名
    
    返回:
        dict: 攻击结果
    """
    if not n or not sf:
        return {'success': False, 'text': "请填写模数n和错误签名sf"}
    
    try:
        n = int(n)
        e = int(e) if e else 65537
        sf = int(sf)
        m = int(m) if m else None
        sv = int(sv) if sv else None
    except ValueError as ex:
        return {'success': False, 'text': f"输入格式错误: {str(ex)}"}
    
    if m is not None:
        result = attack_known_message(n, e, m, sf)
        if result:
            p, q = result
            phi = (p - 1) * (q - 1)
            return {
                'success': True,
                'text': f"攻击成功!\n\n使用消息和错误签名恢复因子:\n\np = {p}\nq = {q}\n\nφ(n) = {phi}",
                'p': p,
                'q': q,
                'phi': phi
            }
    
    if sv is not None:
        result = attack_known_valid_signature(n, e, sv, sf)
        if result:
            p, q = result
            phi = (p - 1) * (q - 1)
            return {
                'success': True,
                'text': f"攻击成功!\n\n使用正确签名和错误签名恢复因子:\n\np = {p}\nq = {q}\n\nφ(n) = {phi}",
                'p': p,
                'q': q,
                'phi': phi
            }
    
    return {
        'success': False,
        'text': "CRT故障攻击失败\n\n可能原因:\n• 错误签名实际上没有故障\n• 需要提供消息m或正确签名sv\n• 签名不是来自RSA-CRT"
    }
