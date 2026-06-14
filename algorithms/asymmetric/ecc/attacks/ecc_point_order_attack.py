"""ECC 点阶分析。"""

from algorithms.asymmetric.ecc.attacks.ecc_math import is_on_curve, parse_int, point_order


ATTACK_NAME = "ECC点阶分析"
ATTACK_DESC = "计算小曲线点阶，辅助识别弱子群"
ATTACK_HINT = "输入 toy/CTF 小曲线参数和点坐标，计算点阶。适合分析弱子群或构造小阶离散对数。"

INPUT_FIELDS = [
    {'name': 'p', 'label': '素数 p', 'type': 'text', 'default': '', 'placeholder': '例如 97', 'required': True},
    {'name': 'a', 'label': '曲线参数 a', 'type': 'text', 'default': '', 'placeholder': '例如 2', 'required': True},
    {'name': 'b', 'label': '曲线参数 b', 'type': 'text', 'default': '', 'placeholder': '例如 3', 'required': True},
    {'name': 'x', 'label': '点 x', 'type': 'text', 'default': '', 'placeholder': '例如 3', 'required': True},
    {'name': 'y', 'label': '点 y', 'type': 'text', 'default': '', 'placeholder': '例如 6', 'required': True},
    {'name': 'max_steps', 'label': '最大步数', 'type': 'text', 'default': '', 'placeholder': '可留空', 'required': False},
]


def attack(p, a, b, x, y, max_steps=''):
    try:
        p = parse_int(p)
        a = parse_int(a)
        b = parse_int(b)
        x = parse_int(x)
        y = parse_int(y)
        max_steps = parse_int(max_steps)
    except Exception as ex:
        return {'success': False, 'text': f'输入格式错误: {ex}'}

    point = (x % p, y % p)
    if not is_on_curve(point, a, b, p):
        return {'success': False, 'text': '输入点不在曲线上'}

    order = point_order(point, a, p, max_steps=max_steps)
    if order is None:
        return {'success': False, 'text': '在给定步数内未找到点阶'}

    return {
        'success': True,
        'text': f'分析成功!\n\n点 P = ({point[0]}, {point[1]})\n点阶 = {order}',
        'order': order,
    }
