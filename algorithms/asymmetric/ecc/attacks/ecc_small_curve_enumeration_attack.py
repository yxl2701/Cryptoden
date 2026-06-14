"""小曲线点枚举与弱曲线分析。"""

from algorithms.asymmetric.ecc.attacks.ecc_math import parse_int


ATTACK_NAME = "ECC小曲线枚举"
ATTACK_DESC = "枚举小有限域曲线点数并辅助判断是否偏弱"
ATTACK_HINT = "适合 toy curve/CTF。输入 p、a、b，枚举 E(Fp) 点数、j 不变量和奇异性。p 太大时不适合。"

INPUT_FIELDS = [
    {'name': 'p', 'label': '素数 p', 'type': 'text', 'default': '', 'placeholder': '例如 97', 'required': True},
    {'name': 'a', 'label': '曲线参数 a', 'type': 'text', 'default': '', 'placeholder': '例如 2', 'required': True},
    {'name': 'b', 'label': '曲线参数 b', 'type': 'text', 'default': '', 'placeholder': '例如 3', 'required': True},
    {'name': 'max_p', 'label': '允许最大p', 'type': 'text', 'default': '2000', 'placeholder': '默认 2000', 'required': False},
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


def _quadratic_residue_counts(p):
    counts = [0] * p
    for y in range(p):
        counts[(y * y) % p] += 1
    return counts


def _small_factor_hints(count):
    weak_reasons = []
    if count == 0:
        return weak_reasons
    if count % 2 == 0:
        weak_reasons.append('群阶含小因子2')
    if count % 3 == 0:
        weak_reasons.append('群阶含小因子3')
    if count % 5 == 0:
        weak_reasons.append('群阶含小因子5')
    if count % 7 == 0:
        weak_reasons.append('群阶含小因子7')
    return weak_reasons


def attack(p, a, b, max_p='2000', use_sage='auto'):
    try:
        p = parse_int(p)
        a = parse_int(a)
        b = parse_int(b)
        max_p = parse_int(max_p)
    except Exception as ex:
        return {'success': False, 'text': f'输入格式错误: {ex}'}

    if p is None or a is None or b is None:
        return {'success': False, 'text': '请填写所有参数'}
    if max_p is None:
        max_p = 2000
    if p > max_p:
        return {'success': False, 'text': f'p={p} 超出枚举上限 {max_p}，请只用于小曲线'}

    discriminant = (-16 * (4 * a * a * a + 27 * b * b)) % p
    singular = discriminant == 0
    if singular:
        return {
            'success': True,
            'text': '分析完成!\n\n检测到奇异曲线：判别式为 0。\n这类曲线不安全，通常可退化为更简单代数结构。',
            'singular': True,
            'discriminant': discriminant,
        }

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
E = EllipticCurve(GF(p), [a, b])
print(json.dumps({{'success': True, 'order': int(E.cardinality()), 'j_invariant': int(E.j_invariant()) if E.j_invariant() != Infinity else None, 'method': 'sage'}}))
"""
        success, result = sage_executor.execute_and_parse(code, timeout=60)
        if success and isinstance(result, dict) and result.get('success'):
            count = int(result['order'])
            j_invariant = result.get('j_invariant')
            trace = p + 1 - count
            weak_reasons = _small_factor_hints(count)
            if count == p:
                weak_reasons.append('anomalous curve (#E(Fp)=p)')
            text = (
                '分析完成!\n\n'
                f'#E(Fp) = {count}\n'
                f'trace = {trace}\n'
                f'判别式 mod p = {discriminant}\n'
                f'j-invariant mod p = {j_invariant}\n'
                f'弱点提示: {", ".join(weak_reasons) if weak_reasons else "未发现明显小因子提示"}\n'
                '加速方式 = SageMath'
            )
            return {
                'success': True,
                'text': text,
                'order': count,
                'trace': trace,
                'singular': False,
                'j_invariant': j_invariant,
                'weak_reasons': weak_reasons,
                'method': 'sage',
            }
        if sage_mode == 'true':
            error = result.get('error', 'SageMath执行失败') if isinstance(result, dict) else 'SageMath执行失败'
            return {'success': False, 'text': error}

    count = 1
    residue_counts = _quadratic_residue_counts(p)
    for x in range(p):
        rhs = (x * x * x + a * x + b) % p
        count += residue_counts[rhs]

    numerator = (1728 * 4 * a * a * a) % p
    denominator = (4 * a * a * a + 27 * b * b) % p
    if denominator == 0:
        j_invariant = None
    else:
        j_invariant = (numerator * pow(denominator, -1, p)) % p

    trace = p + 1 - count
    weak_reasons = _small_factor_hints(count)
    if count == p:
        weak_reasons.append('anomalous curve (#E(Fp)=p)')

    text = (
        '分析完成!\n\n'
        f'#E(Fp) = {count}\n'
        f'trace = {trace}\n'
        f'判别式 mod p = {discriminant}\n'
        f'j-invariant mod p = {j_invariant}\n'
        f'弱点提示: {", ".join(weak_reasons) if weak_reasons else "未发现明显小因子提示"}'
    )
    return {
        'success': True,
        'text': text,
        'order': count,
        'trace': trace,
        'singular': False,
        'j_invariant': j_invariant,
        'weak_reasons': weak_reasons,
    }
