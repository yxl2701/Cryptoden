"""
Pollard's Rho分解攻击模块
=========================

【攻击原理】
Pollard's Rho是一种概率性的整数分解算法，适用于分解大整数。

算法基于生日悖论和Floyd的循环检测算法。
通过迭代函数 f(x) = x^2 + c mod n，寻找模n的因子。

【适用条件】
1. 模数n有小的因子
2. 因子p满足 p-1 有小的平滑因子时效果更好

【攻击步骤】
1. 选择随机起始值x和常数c
2. 迭代计算 x = x^2 + c mod n
3. 使用Floyd循环检测：检查 gcd(|x - y|, n)
4. 如果gcd > 1且gcd < n，则找到因子

【CTF例题】
已知: n（因子不太大）
求: p, q

【参考】
- Pollard's Rho算法
- Brent改进算法
"""

ATTACK_NAME = "PollardRho分解"
ATTACK_DESC = "通用分解算法"
ATTACK_HINT = """【攻击说明】
Pollard's Rho是一种通用的整数分解算法。

输入参数:
- 模数n: 要分解的模数
- 最大迭代: 最大尝试次数

适用: 当n有不太大的因子时效果较好"""

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
import random

# gmpy2 加速（如果可用）
try:
    import gmpy2
    HAS_GMPY2 = True
except ImportError:
    HAS_GMPY2 = False


def _gcd(a, b):
    """快速 GCD，优先使用 gmpy2"""
    if HAS_GMPY2:
        return int(gmpy2.gcd(a, b))
    return math.gcd(a, b)


def pollard_rho(n, max_iter=1000000):
    """
    Pollard's Rho算法分解n（含Brent改进 + gmpy2加速）
    
    参数:
        n: 要分解的数
        max_iter: 最大迭代次数
    
    返回:
        找到的因子，或None
    """
    if n % 2 == 0:
        return 2
    
    if n % 3 == 0:
        return 3
    
    random.seed(42)
    
    for attempt in range(10):
        c = random.randrange(1, n - 1)
        x = random.randrange(2, n - 1)
        y = x
        d = 1
        power = 1
        lam = 0
        
        f = lambda x: (x * x + c) % n
        
        count = 0
        while d == 1 and count < max_iter:
            if power == lam:
                x = y
                power *= 2
                lam = 0
            
            y = f(y)
            lam += 1
            count += 1
            
            # 批量 GCD：每 100 步算一次，减少大数计算开销
            if count % 100 == 0:
                d = _gcd(abs(x - y), n)
        
        if d != 1 and d != n:
            return d
    
    return None


def attack(n, max_iter='1000000'):
    """
    执行Pollard's Rho分解攻击
    
    参数:
        n: 要分解的模数
        max_iter: 最大迭代次数
    
    返回:
        dict: 攻击结果
    """
    if not n:
        return {'success': False, 'text': "请输入模数n"}
    
    try:
        n = int(n)
        max_iter = int(max_iter) if max_iter else 1000000
    except ValueError as ex:
        return {'success': False, 'text': f"输入格式错误: {str(ex)}"}
    
    if n == 1:
        return {'success': False, 'text': "n不能等于1"}
    
    # gmpy2 加速试除（用小素数快速过滤）
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
    for small_prime in small_primes:
        if n % small_prime == 0:
            p = small_prime
            q = n // p
            phi = (p - 1) * (q - 1)
            return {
                'success': True,
                'text': f"分解成功!\n\n发现小因子:\np = {p}\nq = {q}\n\nφ(n) = {phi}",
                'p': p,
                'q': q,
                'phi': phi
            }
    
    p = pollard_rho(n, max_iter)
    
    if p and p != n:
        q = n // p
        phi = (p - 1) * (q - 1)
        return {
            'success': True,
            'text': f"分解成功!\n\np = {p}\nq = {q}\n\nφ(n) = {phi}",
            'p': p,
            'q': q,
            'phi': phi
        }
    
    return {
        'success': False,
        'text': f"Pollard's Rho分解失败\n\n已迭代 {max_iter} 次\n\n可能原因:\n• n的因子太大\n• 建议尝试Fermat分解或其他方法"
    }
