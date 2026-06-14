"""
ECC ECDSA nonce重用恢复攻击
=========================
"""

from hashlib import new as hash_new


ATTACK_NAME = "ECC ECDSA nonce重用恢复"
ATTACK_DESC = "从重复nonce的ECDSA签名恢复私钥"
ATTACK_HINT = """【攻击说明】
当两次ECDSA签名复用同一个nonce时，可恢复私钥d。

输入参数:
- n: 曲线阶
- r: 签名r
- s1/s2: 两个签名的s值
- z1/z2: 两条消息对应的哈希截断值；若留空则使用message1/message2自动计算
- message1/message2: 可选原文
- hash_algorithm: 可选哈希算法，默认SHA256
"""

INPUT_FIELDS = [
    {'name': 'n', 'label': '曲线阶 n', 'type': 'text', 'default': '', 'placeholder': '0x...', 'required': True},
    {'name': 'r', 'label': '签名 r', 'type': 'text', 'default': '', 'placeholder': '0x...', 'required': True},
    {'name': 's1', 'label': '签名 s1', 'type': 'text', 'default': '', 'placeholder': '0x...', 'required': True},
    {'name': 's2', 'label': '签名 s2', 'type': 'text', 'default': '', 'placeholder': '0x...', 'required': True},
    {'name': 'z1', 'label': '消息哈希 z1', 'type': 'text', 'default': '', 'placeholder': '可留空', 'required': False},
    {'name': 'z2', 'label': '消息哈希 z2', 'type': 'text', 'default': '', 'placeholder': '可留空', 'required': False},
    {'name': 'message1', 'label': '消息1', 'type': 'textarea', 'default': '', 'placeholder': '可留空，留空则使用z1', 'required': False},
    {'name': 'message2', 'label': '消息2', 'type': 'textarea', 'default': '', 'placeholder': '可留空，留空则使用z2', 'required': False},
    {
        'name': 'hash_algorithm',
        'label': '哈希算法',
        'type': 'choice',
        'default': 'SHA256',
        'choices': ['SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512'],
        'choice_labels': ['SHA-1', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512'],
        'required': False,
    },
]


def _parse_int(value):
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return int(text, 0)


def _mod_inverse(a, n):
    a %= n
    if a == 0:
        return None
    t, new_t = 0, 1
    r, new_r = n, a
    while new_r:
        q = r // new_r
        t, new_t = new_t, t - q * new_t
        r, new_r = new_r, r - q * new_r
    if r != 1:
        return None
    return t % n


def _hash_to_int(message, hash_algorithm, n_bits):
    digest = hash_new(str(hash_algorithm).replace('-', '').lower(), message.encode('utf-8')).digest()
    digest_bits = len(digest) * 8
    value = int.from_bytes(digest, 'big')
    if digest_bits > n_bits:
        value >>= digest_bits - n_bits
    return value


def attack(n, r, s1, s2, z1='', z2='', message1='', message2='', hash_algorithm='SHA256'):
    if not all([n, r, s1, s2]):
        return {'success': False, 'text': '请填写n、r、s1、s2'}

    try:
        n = _parse_int(n)
        r = _parse_int(r)
        s1 = _parse_int(s1)
        s2 = _parse_int(s2)
        z1 = _parse_int(z1)
        z2 = _parse_int(z2)
    except Exception as ex:
        return {'success': False, 'text': f'输入格式错误: {ex}'}

    if z1 is None:
        if not message1:
            return {'success': False, 'text': '请提供z1或message1'}
        z1 = _hash_to_int(message1, hash_algorithm, n.bit_length())
    if z2 is None:
        if not message2:
            return {'success': False, 'text': '请提供z2或message2'}
        z2 = _hash_to_int(message2, hash_algorithm, n.bit_length())

    if n <= 1 or r <= 0 or s1 <= 0 or s2 <= 0:
        return {'success': False, 'text': '参数必须为正整数'}
    if s1 == s2:
        return {'success': False, 'text': 's1与s2不能相同'}

    denom = (s1 - s2) % n
    inv = _mod_inverse(denom, n)
    if inv is None:
        return {'success': False, 'text': '无法计算nonce，分母与n不互质'}

    k = ((z1 - z2) * inv) % n
    r_inv = _mod_inverse(r, n)
    if r_inv is None:
        return {'success': False, 'text': 'r与n不互质，无法恢复私钥'}

    d = ((s1 * k - z1) * r_inv) % n

    return {
        'success': True,
        'text': f'攻击成功!\n\nnonce k = {k}\n私钥 d = {d}\n',
        'k': k,
        'd': d,
    }
