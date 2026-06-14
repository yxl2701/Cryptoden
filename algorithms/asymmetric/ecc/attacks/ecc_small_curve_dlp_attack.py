"""小曲线 ECC 离散对数攻击。"""

from algorithms.asymmetric.ecc.attacks.ecc_math import (
    discrete_log_bsgs,
    is_on_curve,
    parse_int,
    point_order,
)


ATTACK_NAME = "ECC小曲线离散对数"
ATTACK_DESC = "对小阶/CTF toy 曲线使用 BSGS 求 d，使 Q=dG"
ATTACK_HINT = "仅适合小曲线或小阶子群。输入 p、a、b、G、Q，可选 order_bound；留空时先估计 G 的点阶。"

INPUT_FIELDS = [
    {'name': 'p', 'label': '素数 p', 'type': 'text', 'default': '', 'placeholder': '例如 97', 'required': True},
    {'name': 'a', 'label': '曲线参数 a', 'type': 'text', 'default': '', 'placeholder': '例如 2', 'required': True},
    {'name': 'b', 'label': '曲线参数 b', 'type': 'text', 'default': '', 'placeholder': '例如 3', 'required': True},
    {'name': 'gx', 'label': '基点 Gx', 'type': 'text', 'default': '', 'placeholder': '例如 3', 'required': True},
    {'name': 'gy', 'label': '基点 Gy', 'type': 'text', 'default': '', 'placeholder': '例如 6', 'required': True},
    {'name': 'qx', 'label': '目标点 Qx', 'type': 'text', 'default': '', 'placeholder': '例如 80', 'required': True},
    {'name': 'qy', 'label': '目标点 Qy', 'type': 'text', 'default': '', 'placeholder': '例如 10', 'required': True},
    {'name': 'order_bound', 'label': '搜索上界', 'type': 'text', 'default': '', 'placeholder': '可留空', 'required': False},
    {
        'name': 'use_sage',
        'label': '使用SageMath',
        'type': 'choice',
        'default': 'auto',
        'choices': ['auto', 'false', 'true'],
        'choice_labels': ['自动', '关闭', '强制'],
        'required': False,
    },
]


def attack(p, a, b, gx, gy, qx, qy, order_bound='', use_sage='auto'):
    try:
        p = parse_int(p)
        a = parse_int(a)
        b = parse_int(b)
        gx = parse_int(gx)
        gy = parse_int(gy)
        qx = parse_int(qx)
        qy = parse_int(qy)
        order_bound = parse_int(order_bound)
    except Exception as ex:
        return {'success': False, 'text': f'输入格式错误: {ex}'}

    g = (gx % p, gy % p)
    q = (qx % p, qy % p)
    if not is_on_curve(g, a, b, p):
        return {'success': False, 'text': '基点 G 不在曲线上'}
    if not is_on_curve(q, a, b, p):
        return {'success': False, 'text': '目标点 Q 不在曲线上'}

    if order_bound is None:
        order_bound = point_order(g, a, p)
        if order_bound is None:
            return {'success': False, 'text': '无法自动估计基点阶，请手动填写搜索上界'}

    try:
        from core.sage_executor import sage_executor
    except Exception:
        sage_executor = None

    sage_mode = str(use_sage).strip().lower()
    if sage_mode in ('1', 'yes', 'true', 'on'):
        sage_mode = 'true'
    if sage_mode in ('0', 'no', 'false', 'off'):
        sage_mode = 'false'

    if sage_mode != 'false' and sage_executor is not None and sage_executor.is_available():
        code = f"""
import json
p = {p}
a = {a}
b = {b}
gx = {g[0]}
gy = {g[1]}
qx = {q[0]}
qy = {q[1]}
order_bound = {order_bound}
E = EllipticCurve(GF(p), [a, b])
G = E(gx, gy)
Q = E(qx, qy)
try:
    d = Q.discrete_log(G)
    print(json.dumps({{'success': True, 'd': int(d), 'method': 'sage'}}))
except Exception as ex:
    print(json.dumps({{'success': False, 'error': str(ex)}}))
"""
        success, result = sage_executor.execute_and_parse(code, timeout=60)
        if success and isinstance(result, dict) and result.get('success'):
            d = int(result['d'])
            return {
                'success': True,
                'text': f'攻击成功!\n\n离散对数 d = {d}\n满足 Q = dG\n搜索上界 = {order_bound}\n加速方式 = SageMath',
                'd': d,
                'order_bound': order_bound,
                'method': 'sage',
            }
        if sage_mode == 'true':
            error = result.get('error', 'SageMath执行失败') if isinstance(result, dict) else 'SageMath执行失败'
            return {'success': False, 'text': error}

    d = discrete_log_bsgs(g, q, a, p, order_bound)
    if d is None:
        return {'success': False, 'text': '在给定范围内未找到离散对数'}

    return {
        'success': True,
        'text': f'攻击成功!\n\n离散对数 d = {d}\n满足 Q = dG\n搜索上界 = {order_bound}',
        'd': d,
        'order_bound': order_bound,
    }
