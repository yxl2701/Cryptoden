"""
因数分解攻击模块
================

【攻击原理】
尝试多种方法分解RSA模数n，适用于n较小或有特殊结构的情况。

【分解方法】
1. 试除法(Trial Division): 适用于n有小因子
2. Pollard Rho: 适用于n有中等大小的因子
3. Pollard p-1: 适用于p-1光滑
4. Fermat分解: 适用于p和q接近

【适用条件】
1. n较小（可以暴力分解）
2. n有特殊结构（小因子、光滑数等）

【CTF例题】
已知: n（较小或有特殊结构）
求: p, q

解法:
1. 自动尝试多种分解方法
2. 或手动选择特定方法

【参考】
- 因数分解算法
- factordb.com
"""

ATTACK_NAME = "因数分解攻击"
ATTACK_DESC = "n较小或有已知因子时分解"
ATTACK_HINT = """【攻击说明】
尝试多种方法分解n。

输入参数:
- 模数n: 要分解的RSA模数
- 分解方法: auto(自动)/trial(试除)/rho/f1/fermat
- 试除上限: 试除法搜索上限

自动模式会依次尝试所有方法"""

INPUT_FIELDS = [
    {
        'name': 'n',
        'label': '模数 n',
        'type': 'text',
        'default': '',
        'placeholder': '输入要分解的模数n',
        'required': True
    },
    {
        'name': 'method',
        'label': '分解方法',
        'type': 'combo',
        'default': 'auto',
        'options': ['auto', 'trial', 'rho', 'p1', 'fermat'],
        'required': False
    },
    {
        'name': 'limit',
        'label': '试除上限',
        'type': 'number',
        'default': '1000000',
        'placeholder': '试除法上限',
        'required': False
    }
]

import math
import random


def trial_division(n, limit):
    """试除法"""
    if n % 2 == 0:
        return (2, n // 2)
    for i in range(3, min(limit, int(n**0.5) + 1), 2):
        if n % i == 0:
            return (i, n // i)
    return None


def pollard_rho(n, max_iter=1000000):
    """Pollard rho算法"""
    if n % 2 == 0:
        return (2, n // 2)
    
    x = random.randint(2, n - 1)
    y = x
    c = random.randint(1, n - 1)
    d = 1
    
    f = lambda x: (x * x + c) % n
    
    while d == 1:
        x = f(x)
        y = f(f(y))
        d = math.gcd(abs(x - y), n)
        
        max_iter -= 1
        if max_iter <= 0:
            return None
    
    if d != n:
        return (d, n // d)
    return None


def fermat_factor(n, max_iter=1000000):
    """Fermat分解"""
    a = math.isqrt(n)
    if a * a == n:
        return (a, a)
    
    a += 1
    b2 = a * a - n
    
    for _ in range(max_iter):
        b = math.isqrt(b2)
        if b * b == b2:
            return (a + b, a - b)
        a += 1
        b2 = a * a - n
    
    return None


def pollard_p1(n, B=100000):
    """Pollard p-1分解"""
    a = 2
    for j in range(2, B):
        a = pow(a, j, n)
        d = math.gcd(a - 1, n)
        if 1 < d < n:
            return (d, n // d)
    return None


def attack(n, method='auto', limit='1000000'):
    """
    执行因数分解攻击
    
    参数:
        n: 要分解的模数
        method: 分解方法 (auto/trial/rho/p1/fermat)
        limit: 试除上限
    
    返回:
        dict: 攻击结果
    """
    if not n:
        return {'success': False, 'text': "请输入模数n"}
    
    try:
        n = int(n)
        limit = int(limit) if limit else 1000000
    except ValueError as ex:
        return {'success': False, 'text': f"输入格式错误: {str(ex)}"}
    
    if n % 2 == 0:
        p, q = 2, n // 2
        phi = (p - 1) * (q - 1)
        return {
            'success': True,
            'p': str(p),
            'q': str(q),
            'phi': str(phi),
            'text': f"分解成功!\n\np = {p}\nq = {q}\n\nφ(n) = {phi}"
        }
    
    result = None
    
    if method == 'auto':
        result = trial_division(n, limit)
        if not result:
            result = pollard_rho(n)
        if not result:
            result = fermat_factor(n, limit)
    elif method == 'trial':
        result = trial_division(n, limit)
    elif method == 'rho':
        result = pollard_rho(n)
    elif method == 'p1':
        result = pollard_p1(n)
    elif method == 'fermat':
        result = fermat_factor(n, limit)
    
    if result:
        p, q = result
        phi = (p - 1) * (q - 1)
        return {
            'success': True,
            'p': str(p),
            'q': str(q),
            'phi': str(phi),
            'text': f"分解成功!\n\np = {p}\nq = {q}\n\nφ(n) = {phi}\n\nn = {p} × {q}"
        }
    
    return {
        'success': False,
        'text': f"分解失败\n\n已尝试方法: {method}\n上限: {limit}\n\n建议:\n• 增大上限\n• 尝试其他方法\n• 使用factordb.com"
    }
