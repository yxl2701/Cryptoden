"""ECDSA 已知 nonce 恢复私钥。"""

from algorithms.asymmetric.ecc.attacks.ecc_math import mod_inverse, parse_int


ATTACK_NAME = "ECDSA已知Nonce恢复"
ATTACK_DESC = "从单个签名和已知k恢复ECDSA私钥"
ATTACK_HINT = "输入 n、r、s、z、k，恢复私钥 d。适合题目直接泄露或侧信道得到 nonce 的场景。"

INPUT_FIELDS = [
    {'name': 'n', 'label': '曲线阶 n', 'type': 'text', 'default': '', 'placeholder': '0x...', 'required': True},
    {'name': 'r', 'label': '签名 r', 'type': 'text', 'default': '', 'placeholder': '0x...', 'required': True},
    {'name': 's', 'label': '签名 s', 'type': 'text', 'default': '', 'placeholder': '0x...', 'required': True},
    {'name': 'z', 'label': '消息哈希 z', 'type': 'text', 'default': '', 'placeholder': '0x...', 'required': True},
    {'name': 'k', 'label': 'Nonce k', 'type': 'text', 'default': '', 'placeholder': '0x...', 'required': True},
]


def attack(n, r, s, z, k):
    try:
        n = parse_int(n)
        r = parse_int(r)
        s = parse_int(s)
        z = parse_int(z)
        k = parse_int(k)
    except Exception as ex:
        return {'success': False, 'text': f'输入格式错误: {ex}'}

    if not all(v is not None for v in (n, r, s, z, k)):
        return {'success': False, 'text': '请填写所有参数'}

    r_inv = mod_inverse(r, n)
    if r_inv is None:
        return {'success': False, 'text': 'r与n不互质，无法恢复私钥'}

    d = ((s * k - z) * r_inv) % n
    return {
        'success': True,
        'text': f'攻击成功!\n\n私钥 d = {d}\n验证公式: d = (s*k-z)/r mod n',
        'd': d,
    }
