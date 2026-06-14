"""ECDSA 线性 nonce 关系攻击。"""

from algorithms.asymmetric.ecc.attacks.ecc_math import mod_inverse, parse_int


ATTACK_NAME = "ECDSA线性Nonce关系"
ATTACK_DESC = "已知 k2 = alpha*k1 + beta 时恢复私钥"
ATTACK_HINT = "输入两组签名及 alpha/beta，其中 k2 = alpha*k1 + beta。delta攻击和比例攻击都是它的特例。"

INPUT_FIELDS = [
    {'name': 'n', 'label': '曲线阶 n', 'type': 'text', 'default': '', 'placeholder': '0x...', 'required': True},
    {'name': 's1', 'label': '签名1 s', 'type': 'text', 'default': '', 'placeholder': '0x...', 'required': True},
    {'name': 'z1', 'label': '消息1哈希 z1', 'type': 'text', 'default': '', 'placeholder': '0x...', 'required': True},
    {'name': 's2', 'label': '签名2 s', 'type': 'text', 'default': '', 'placeholder': '0x...', 'required': True},
    {'name': 'z2', 'label': '消息2哈希 z2', 'type': 'text', 'default': '', 'placeholder': '0x...', 'required': True},
    {'name': 'alpha', 'label': 'alpha', 'type': 'text', 'default': '1', 'placeholder': 'k2 = alpha*k1 + beta', 'required': True},
    {'name': 'beta', 'label': 'beta', 'type': 'text', 'default': '0', 'placeholder': 'k2 = alpha*k1 + beta', 'required': True},
    {'name': 'r', 'label': '公共签名 r', 'type': 'text', 'default': '', 'placeholder': '0x...', 'required': True},
]


def attack(n, s1, z1, s2, z2, alpha='1', beta='0', r=''):
    try:
        n = parse_int(n)
        s1 = parse_int(s1)
        z1 = parse_int(z1)
        s2 = parse_int(s2)
        z2 = parse_int(z2)
        alpha = parse_int(alpha)
        beta = parse_int(beta)
        r = parse_int(r)
    except Exception as ex:
        return {'success': False, 'text': f'输入格式错误: {ex}'}

    if not all(v is not None for v in (n, s1, z1, s2, z2, alpha, beta, r)):
        return {'success': False, 'text': '请填写所有参数'}

    denominator = (s1 - alpha * s2) % n
    denominator_inv = mod_inverse(denominator, n)
    if denominator_inv is None:
        return {'success': False, 'text': 's1-alpha*s2与n不互质，无法恢复nonce'}

    k1 = ((z1 - z2 + s2 * beta) * denominator_inv) % n
    k2 = (alpha * k1 + beta) % n
    r_inv = mod_inverse(r, n)
    if r_inv is None:
        return {'success': False, 'text': 'r与n不互质，无法恢复私钥'}

    d = ((s1 * k1 - z1) * r_inv) % n
    return {
        'success': True,
        'text': f'攻击成功!\n\nk1 = {k1}\nk2 = {k2}\n私钥 d = {d}',
        'k1': k1,
        'k2': k2,
        'd': d,
    }
