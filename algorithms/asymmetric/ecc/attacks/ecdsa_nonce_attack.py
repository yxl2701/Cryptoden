"""
ECDSA Nonce重用攻击模块
=======================

【攻击原理】
ECDSA签名中，如果两次签名使用了相同的nonce k，则可以恢复私钥。

签名公式:
- r = (k * G).x mod n
- s1 = k^(-1) * (m1 + r * d) mod n
- s2 = k^(-1) * (m2 + r * d) mod n

当nonce相同时，r相同：
- s1 - s2 = k^(-1) * (m1 - m2) mod n
- k = (m1 - m2) / (s1 - s2) mod n

然后：
- d = (s1 * k - m1) / r mod n

【适用条件】
1. 两次签名使用了相同的nonce
2. 两次签名的r值相同
3. 已知消息的哈希值

【CTF例题】
已知: n, m1, r, s1, m2, r, s2
求: 私钥d

【参考】
- ECDSA nonce重用攻击
- 私钥恢复
"""

ATTACK_NAME = "ECDSA Nonce重用"
ATTACK_DESC = "相同nonce恢复私钥"
ATTACK_HINT = """【攻击说明】
当两次ECDSA签名使用相同的nonce时，可以恢复私钥。

输入参数:
- 阶数n: 椭圆曲线的阶
- 消息1哈希: m1
- 签名1: r1, s1
- 消息2哈希: m2
- 签名2: r2, s2

条件: r1 == r2 (表示nonce相同)"""

INPUT_FIELDS = [
    {
        'name': 'n',
        'label': '曲线阶 n',
        'type': 'text',
        'default': '',
        'placeholder': '输入椭圆曲线阶n',
        'required': True
    },
    {
        'name': 'm1',
        'label': '消息1哈希',
        'type': 'text',
        'default': '',
        'placeholder': 'm1',
        'required': True
    },
    {
        'name': 'r1',
        'label': '签名1 r',
        'type': 'text',
        'default': '',
        'placeholder': 'r1',
        'required': True
    },
    {
        'name': 's1',
        'label': '签名1 s',
        'type': 'text',
        'default': '',
        'placeholder': 's1',
        'required': True
    },
    {
        'name': 'm2',
        'label': '消息2哈希',
        'type': 'text',
        'default': '',
        'placeholder': 'm2',
        'required': True
    },
    {
        'name': 'r2',
        'label': '签名2 r',
        'type': 'text',
        'default': '',
        'placeholder': 'r2',
        'required': True
    },
    {
        'name': 's2',
        'label': '签名2 s',
        'type': 'text',
        'default': '',
        'placeholder': 's2',
        'required': True
    }
]


def extended_gcd(a, b):
    """扩展欧几里得算法"""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def mod_inverse(a, n):
    """计算模逆"""
    a = a % n
    if a < 0:
        a += n
    gcd, x, _ = extended_gcd(a, n)
    if gcd != 1:
        return None
    return (x % n + n) % n


def solve_congruence(a, b, n):
    """解同余方程 ax ≡ b (mod n)"""
    a = a % n
    b = b % n
    
    gcd, x, _ = extended_gcd(a, n)
    
    if b % gcd != 0:
        return []
    
    solutions = []
    a1 = a // gcd
    b1 = b // gcd
    n1 = n // gcd
    
    x0 = (b1 * mod_inverse(a1, n1)) % n1
    
    for i in range(gcd):
        solutions.append((x0 + i * n1) % n)
    
    return solutions


def attack(n, m1, r1, s1, m2, r2, s2):
    """
    执行ECDSA Nonce重用攻击
    
    参数:
        n: 曲线阶
        m1, r1, s1: 第一个消息和签名
        m2, r2, s2: 第二个消息和签名
    
    返回:
        dict: 攻击结果
    """
    if not all([n, m1, r1, s1, m2, r2, s2]):
        return {'success': False, 'text': "请填写所有参数"}
    
    try:
        n = int(n)
        m1 = int(m1)
        r1 = int(r1)
        s1 = int(s1)
        m2 = int(m2)
        r2 = int(r2)
        s2 = int(s2)
    except ValueError as ex:
        return {'success': False, 'text': f"输入格式错误: {str(ex)}"}
    
    if r1 != r2:
        return {'success': False, 'text': f"r1 ≠ r2，两次签名使用了不同的nonce\n\nr1 = {r1}\nr2 = {r2}"}
    
    r = r1
    
    results = []
    
    for k in solve_congruence(int(s1 - s2), int(m1 - m2), int(n)):
        for d in solve_congruence(int(r), int(k * s1 - m1), int(n)):
            results.append((k, d))
    
    if not results:
        return {'success': False, 'text': "无法求解，请检查输入参数"}
    
    result_text = f"找到 {len(results)} 个可能的解:\n\n"
    
    for i, (k, d) in enumerate(results[:5]):
        result_text += f"解 {i+1}:\n"
        result_text += f"  nonce k = {k}\n"
        result_text += f"  私钥 d = {d}\n\n"
    
    if len(results) > 5:
        result_text += f"... 还有 {len(results) - 5} 个解\n"
    
    result_text += "验证方法: 使用恢复的私钥d重新签名，检查是否得到相同的签名"
    
    return {
        'success': True,
        'text': f"攻击成功!\n\n{result_text}",
        'k': results[0][0] if results else None,
        'd': results[0][1] if results else None
    }
