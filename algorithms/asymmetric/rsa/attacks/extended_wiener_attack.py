"""
扩展Wiener攻击模块
==================

【攻击原理】
扩展Wiener攻击是Wiener攻击的改进版本，可以处理更大的私钥d。

Wiener攻击限制: d < n^0.25 / 3
扩展Wiener攻击可以突破这个限制，处理更大的d。

算法通过枚举更多的连分数渐近分数组合来搜索可能的私钥。

【适用条件】
1. 私钥d较小（比标准Wiener攻击范围更大）
2. 公钥e较大

【CTF例题】
已知: n, e（e很大）
求: 私钥d

【参考】
- Dujella, "Continued fractions and RSA with small secret exponent"
- 扩展连分数攻击
"""

ATTACK_NAME = "扩展Wiener攻击"
ATTACK_DESC = "改进的Wiener攻击"
ATTACK_HINT = """【攻击说明】
扩展Wiener攻击可以处理比标准Wiener攻击更大的私钥d。

输入参数:
- 模数n: RSA模数
- 公钥e: RSA公钥（通常很大）
- 最大s值: 搜索参数（默认2000）
- 最大r值: 搜索参数（默认100）

原理: 枚举更多连分数渐近分数组合"""

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
        'name': 'e',
        'label': '公钥 e',
        'type': 'text',
        'default': '',
        'placeholder': '输入公钥e',
        'required': True
    },
    {
        'name': 'max_s',
        'label': '最大s值',
        'type': 'number',
        'default': '2000',
        'placeholder': '搜索参数',
        'required': False
    },
    {
        'name': 'max_r',
        'label': '最大r值',
        'type': 'number',
        'default': '100',
        'placeholder': '搜索参数',
        'required': False
    }
]

import math


def continued_fraction(num, den):
    """计算连分数展开"""
    cf = []
    while den:
        q = num // den
        cf.append(q)
        num, den = den, num - q * den
    return cf


def convergents(cf):
    """计算渐近分数"""
    n0, n1 = 0, 1
    d0, d1 = 1, 0
    for q in cf:
        n2 = q * n1 + n0
        d2 = q * d1 + d0
        yield n2, d2
        n0, n1 = n1, n2
        d0, d1 = d1, d2


def attack(n, e, max_s='2000', max_r='100'):
    """
    执行扩展Wiener攻击
    
    参数:
        n: 模数
        e: 公钥
        max_s: 最大s值
        max_r: 最大r值
    
    返回:
        dict: 攻击结果
    """
    if not n or not e:
        return {'success': False, 'text': "请填写所有参数"}
    
    try:
        n = int(n)
        e = int(e)
        max_s = int(max_s) if max_s else 2000
        max_r = int(max_r) if max_r else 100
    except ValueError as ex:
        return {'success': False, 'text': f"输入格式错误: {str(ex)}"}
    
    cf = list(continued_fraction(e, n))
    
    for k, d in convergents(cf):
        if k == 0:
            continue
        
        phi = (e * d - 1) // k
        
        if phi <= 0:
            continue
        
        b = n - phi + 1
        delta = b * b - 4 * n
        
        if delta >= 0:
            sqrt_delta = int(math.isqrt(delta))
            if sqrt_delta * sqrt_delta == delta:
                p = (b + sqrt_delta) // 2
                q = (b - sqrt_delta) // 2
                if p * q == n:
                    return {
                        'success': True,
                        'text': f"标准Wiener攻击成功!\n\n私钥 d = {d}\n\np = {p}\nq = {q}\n\nφ(n) = {(p-1)*(q-1)}",
                        'd': d,
                        'p': p,
                        'q': q
                    }
    
    conv_list = list(convergents(cf))
    
    if len(conv_list) < 3:
        return {
            'success': False,
            'text': "扩展Wiener攻击失败\n\n连分数展开不足，无法进行扩展搜索"
        }
    
    for i in range(1, min(len(conv_list) - 2, 20), 2):
        k1, d1 = conv_list[i] if i < len(conv_list) else (1, 1)
        k2, d2 = conv_list[i + 1] if i + 1 < len(conv_list) else (1, 1)
        
        for s in range(max_s):
            for r in range(max_r):
                k = r * k1 + s * k1
                d = r * d1 + s * d1
                
                if k == 0 or d == 0:
                    continue
                
                if (e * d - 1) % k != 0:
                    continue
                
                phi = (e * d - 1) // k
                
                if phi <= 0:
                    continue
                
                b = n - phi + 1
                delta = b * b - 4 * n
                
                if delta >= 0:
                    sqrt_delta = int(math.isqrt(delta))
                    if sqrt_delta * sqrt_delta == delta:
                        p = (b + sqrt_delta) // 2
                        q = (b - sqrt_delta) // 2
                        if p * q == n:
                            return {
                                'success': True,
                                'text': f"扩展Wiener攻击成功!\n\n私钥 d = {d}\n\np = {p}\nq = {q}\n\nφ(n) = {(p-1)*(q-1)}",
                                'd': d,
                                'p': p,
                                'q': q
                            }
    
    return {
        'success': False,
        'text': f"扩展Wiener攻击失败\n\n已搜索:\n• s范围: 0~{max_s}\n• r范围: 0~{max_r}\n\n可能原因:\n• 私钥d太大\n• 建议尝试Boneh-Durfee攻击（需要SageMath）"
    }
