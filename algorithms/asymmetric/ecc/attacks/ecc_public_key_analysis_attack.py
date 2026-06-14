"""
ECC公钥分析辅助
================
"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


ATTACK_NAME = "ECC公钥分析"
ATTACK_DESC = "解析ECC公钥并输出曲线与坐标信息"
ATTACK_HINT = "输入PEM格式公钥，输出曲线名、位数、坐标和编码长度。"

INPUT_FIELDS = [
    {
        'name': 'public_key',
        'label': '公钥',
        'type': 'textarea',
        'default': '',
        'placeholder': '粘贴PEM公钥',
        'required': True,
    },
]


def attack(public_key):
    if not public_key or not str(public_key).strip():
        return {'success': False, 'text': '请提供公钥'}

    try:
        key = serialization.load_pem_public_key(str(public_key).encode('utf-8'), backend=default_backend())
        numbers = key.public_numbers()
        encoded = key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        curve = key.curve
        return {
            'success': True,
            'text': (
                '公钥分析结果\n\n'
                f'曲线: {curve.name}\n'
                f'位数: {curve.key_size}\n'
                f'x: {numbers.x}\n'
                f'y: {numbers.y}\n'
                f'点编码长度: {len(encoded)} bytes\n'
            ),
            'curve': curve.name,
            'x': numbers.x,
            'y': numbers.y,
        }
    except Exception as ex:
        return {'success': False, 'text': f'解析失败: {ex}'}
