"""ECDSA 已知 nonce 差值攻击。"""

from algorithms.asymmetric.ecc.attacks.ecdsa_nonce_affine_attack import attack as affine_attack


ATTACK_NAME = "ECDSA已知Nonce差值"
ATTACK_DESC = "已知 k2 = k1 + delta 时恢复私钥"
ATTACK_HINT = "输入两组签名及 delta，其中 k2 = k1 + delta，可恢复 k1、k2 和私钥 d。"

INPUT_FIELDS = [
    {'name': 'n', 'label': '曲线阶 n', 'type': 'text', 'default': '', 'placeholder': '0x...', 'required': True},
    {'name': 's1', 'label': '签名1 s', 'type': 'text', 'default': '', 'placeholder': '0x...', 'required': True},
    {'name': 'z1', 'label': '消息1哈希 z1', 'type': 'text', 'default': '', 'placeholder': '0x...', 'required': True},
    {'name': 's2', 'label': '签名2 s', 'type': 'text', 'default': '', 'placeholder': '0x...', 'required': True},
    {'name': 'z2', 'label': '消息2哈希 z2', 'type': 'text', 'default': '', 'placeholder': '0x...', 'required': True},
    {'name': 'delta', 'label': '差值 delta', 'type': 'text', 'default': '', 'placeholder': 'k2-k1', 'required': True},
    {'name': 'r', 'label': '公共签名 r', 'type': 'text', 'default': '', 'placeholder': '0x...', 'required': True},
]


def attack(n, s1, z1, s2, z2, delta, r):
    return affine_attack(n=n, s1=s1, z1=z1, s2=s2, z2=z2, alpha='1', beta=delta, r=r)
