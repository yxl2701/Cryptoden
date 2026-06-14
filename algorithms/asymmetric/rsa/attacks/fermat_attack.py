"""
Fermat分解攻击模块
==================

【攻击原理】
当RSA的两个素因子p和q比较接近时，可以使用Fermat分解法快速分解n。

设 n = p * q，且 p > q
设 a = (p + q) / 2，b = (p - q) / 2
则 n = a² - b² = (a+b)(a-b)

当p和q接近时，b很小，a ≈ √n
从 a = ⌈√n⌉ 开始，逐个尝试a值，
检查 a² - n 是否为完全平方数。

【适用条件】
1. p和q比较接近（|p-q|较小）
2. 通常当 |p-q| < n^0.25 时有效

【攻击步骤】
1. 计算 a = ⌈√n⌉
2. 计算 b² = a² - n
3. 如果b²是完全平方数，则 p = a+b, q = a-b
4. 否则 a = a+1，重复步骤2

【CTF例题】
已知: n（p和q接近）
求: p, q

解法:
1. 从 √n 开始向上搜索
2. 找到 a² - n = b² 的情况
3. p = a+b, q = a-b

【参考】
- Fermat分解法
- Pollard rho分解
"""

ATTACK_NAME = "Fermat分解"
ATTACK_DESC = "p和q相近时有效"
ATTACK_HINT = """【攻击说明】
当p和q差距较小时，Fermat分解非常有效。

输入参数:
- 模数n: 要分解的RSA模数
- 最大迭代: 搜索次数上限

原理: n = a² - b² = (a+b)(a-b)
当p≈q时，a≈√n，b很小"""

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
        'name': 'max_iter',
        'label': '最大迭代',
        'type': 'number',
        'default': '1000000',
        'placeholder': '最大迭代次数',
        'required': False
    }
]

import math

from algorithms.asymmetric.rsa.utils import parse_input_value


def attack(n, max_iter='1000000'):
    """
    执行Fermat分解攻击
    
    参数:
        n: 要分解的模数
        max_iter: 最大迭代次数
    
    返回:
        dict: 攻击结果，包含 success, text, p, q, phi 等字段
    """
    if not n:
        return {'success': False, 'text': "请输入模数n"}
    
    try:
        n = parse_input_value(str(n))
        if n is None:
            raise ValueError("n格式无效")
        max_iter = int(max_iter) if max_iter else 1000000
    except ValueError as ex:
        return {'success': False, 'text': f"输入格式错误: {str(ex)}"}
    
    a = math.isqrt(n)
    if a * a == n:
        p, q = a, a
        phi = (p - 1) * (q - 1)
        return {
            'success': True,
            'text': f"分解成功!\n\np = {p}\nq = {q}\n\nφ(n) = {phi}",
            'p': p,
            'q': q,
            'phi': phi
        }
    
    a += 1
    b2 = a * a - n
    
    for i in range(max_iter):
        b = math.isqrt(b2)
        if b * b == b2:
            p = a + b
            q = a - b
            phi = (p - 1) * (q - 1)
            return {
                'success': True,
                'text': f"分解成功!\n\np = {p}\nq = {q}\n\nφ(n) = {phi}\n\n迭代次数: {i+1}",
                'p': p,
                'q': q,
                'phi': phi
            }
        a += 1
        b2 = a * a - n
    
    return {
        'success': False,
        'text': f"Fermat分解失败\n\n已迭代 {max_iter} 次\n\n可能原因:\n• p和q差距较大\n• 建议增大迭代次数或尝试其他方法"
    }
