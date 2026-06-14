"""
已知私钥d恢复因子攻击模块
=========================

【攻击原理】
当已知RSA私钥d时，可以通过概率算法恢复模数n的因子p和q。

由RSA定义: e*d ≡ 1 (mod φ(n))
即: e*d - 1 = k*φ(n)

由于 φ(n) = (p-1)*(q-1)，且 e*d - 1 是偶数，
我们可以利用这个性质来分解n。

【算法步骤】
1. 计算 k = e*d - 1
2. 找到最大的t使得 2^t 整除k
3. 随机选择g，计算 g^(k/2^s) mod n
4. 通过GCD找到因子

【适用条件】
1. 已知私钥d
2. 已知公钥e
3. 已知模数n

【CTF例题】
已知: n, e, d
求: p, q

【参考】
- RSA密钥恢复
- 概率因子分解
"""

ATTACK_NAME = "已知d恢复因子"
ATTACK_DESC = "已知私钥d时恢复因子"
ATTACK_HINT = """【攻击说明】
已知私钥d时可以恢复模数的因子p和q。

输入参数:
- 模数n: RSA模数
- 公钥e: RSA公钥
- 私钥d: RSA私钥

原理: 利用 e*d ≡ 1 (mod φ(n)) 的性质分解n"""

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
        'default': '65537',
        'placeholder': '输入公钥e',
        'required': True
    },
    {
        'name': 'd',
        'label': '私钥 d',
        'type': 'text',
        'default': '',
        'placeholder': '输入私钥d',
        'required': True
    }
]

import math
import random


def attack(n, e, d):
    """
    执行已知d恢复因子攻击
    
    参数:
        n: 模数
        e: 公钥
        d: 私钥
    
    返回:
        dict: 攻击结果
    """
    if not n or not e or not d:
        return {'success': False, 'text': "请填写所有参数"}
    
    try:
        n = int(n)
        e = int(e)
        d = int(d)
    except ValueError as ex:
        return {'success': False, 'text': f"输入格式错误: {str(ex)}"}
    
    k = e * d - 1
    if k <= 0:
        return {'success': False, 'text': "e*d-1必须为正数"}
    
    t = 0
    while k % (2 ** t) == 0:
        t += 1
    t -= 1
    
    if t == 0:
        return {'success': False, 'text': "e*d-1不是偶数，参数可能有误"}
    
    random.seed(42)
    
    for _ in range(100):
        g = random.randrange(2, n)
        
        for s in range(1, t + 1):
            power = k // (2 ** s)
            x = pow(g, power, n)
            
            if x == 1:
                continue
            
            p = math.gcd(x - 1, n)
            
            if 1 < p < n and n % p == 0:
                q = n // p
                phi = (p - 1) * (q - 1)
                return {
                    'success': True,
                    'text': f"攻击成功!\n\np = {p}\nq = {q}\n\nφ(n) = {phi}",
                    'p': p,
                    'q': q,
                    'phi': phi
                }
    
    return {
        'success': False,
        'text': "攻击失败\n\n可能原因:\n• 输入的d不是有效的私钥\n• 需要更多随机尝试次数"
    }
