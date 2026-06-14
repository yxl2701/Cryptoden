"""
LCG参数恢复攻击模块（纯Python版）
=================================

【攻击原理】
线性同余生成器(LCG)的公式为: X_{n+1} = (a * X_n + c) mod m

当已知连续输出时，可以恢复LCG的参数：
- 模数 m: 通过计算差值的GCD恢复
- 乘数 a: 通过连续输出的关系计算
- 增量 c: 通过已知的a和输出计算

【数学推导】
设 y_0, y_1, y_2, y_3 是连续输出
d_0 = y_1 - y_0
d_1 = y_2 - y_1
d_2 = y_3 - y_2

则 m | (d_2 * d_0 - d_1^2)

通过计算多个这样的值的GCD可以恢复m

【适用条件】
1. 已知至少4个连续输出（恢复m）
2. 已知至少3个连续输出（恢复a）
3. 已知至少2个连续输出（恢复c）

【CTF例题】
已知: 连续的LCG输出值
求: 参数 m, a, c

【参考】
- LCG参数恢复
- GCD攻击
"""

ATTACK_NAME = "LCG参数恢复"
ATTACK_DESC = "从输出恢复LCG参数"
ATTACK_HINT = """【攻击说明】
从LCG的连续输出中恢复参数m, a, c。

输入参数:
- 输出序列: 连续的LCG输出值，逗号或换行分隔
- 模数m: 可选，已知时填入
- 乘数a: 可选，已知时填入
- 增量c: 可选，已知时填入

需要输出数量:
- 恢复m: 至少4个
- 恢复a: 至少3个
- 恢复c: 至少2个"""

INPUT_FIELDS = [
    {
        'name': 'outputs',
        'label': '输出序列',
        'type': 'textarea',
        'default': '',
        'placeholder': '输入连续输出值，逗号或换行分隔',
        'required': True
    },
    {
        'name': 'm',
        'label': '模数 m (可选)',
        'type': 'text',
        'default': '',
        'placeholder': '已知时填入',
        'required': False
    },
    {
        'name': 'a',
        'label': '乘数 a (可选)',
        'type': 'text',
        'default': '',
        'placeholder': '已知时填入',
        'required': False
    },
    {
        'name': 'c',
        'label': '增量 c (可选)',
        'type': 'text',
        'default': '',
        'placeholder': '已知时填入',
        'required': False
    }
]

import math


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
    gcd, x, _ = extended_gcd(a % n, n)
    if gcd != 1:
        return None
    return (x % n + n) % n


def is_prime_power(n):
    """检查n是否是素数的幂"""
    if n <= 1:
        return False
    for p in range(2, min(n, 100000)):
        if n % p == 0:
            power = p
            while power < n:
                power *= p
            return power == n
    return True


def recover_modulus(y):
    """从输出序列恢复模数m"""
    m = None
    for i in range(len(y) - 3):
        d0 = y[i + 1] - y[i]
        d1 = y[i + 2] - y[i + 1]
        d2 = y[i + 3] - y[i + 2]
        g = d2 * d0 - d1 * d1
        if g != 0:
            m = g if m is None else math.gcd(g, m)
    return abs(m) if m else None


def recover_multiplier(y, m):
    """从输出序列恢复乘数a"""
    if len(y) < 3:
        return None
    
    x0, x1, x2 = y[0], y[1], y[2]
    denom = (x1 - x0) % m
    numer = (x2 - x1) % m
    
    if math.gcd(denom, m) != 1:
        return None
    
    a = (numer * mod_inverse(denom, m)) % m
    return a


def recover_increment(y, m, a):
    """从输出序列恢复增量c"""
    if len(y) < 2:
        return None
    
    x0, x1 = y[0], y[1]
    c = (x1 - a * x0) % m
    return c


def attack(outputs, m='', a='', c=''):
    """
    执行LCG参数恢复攻击
    
    参数:
        outputs: 输出序列字符串
        m: 模数（可选）
        a: 乘数（可选）
        c: 增量（可选）
    
    返回:
        dict: 攻击结果
    """
    if not outputs:
        return {'success': False, 'text': "请输入输出序列"}
    
    try:
        y = []
        for val in outputs.replace('\n', ',').split(','):
            val = val.strip()
            if val:
                y.append(int(val))
    except ValueError as ex:
        return {'success': False, 'text': f"输出序列格式错误: {str(ex)}"}
    
    if len(y) < 2:
        return {'success': False, 'text': "至少需要2个输出值"}
    
    m_val = int(m) if m else None
    a_val = int(a) if a else None
    c_val = int(c) if c else None
    
    result_text = ""
    
    if m_val is None:
        if len(y) < 4:
            return {'success': False, 'text': "恢复模数m需要至少4个输出值"}
        
        m_val = recover_modulus(y)
        if m_val is None or m_val <= 1:
            return {'success': False, 'text': "无法恢复模数m\n\n可能原因:\n• 输出值不够\n• 输出值有误\n• 请直接提供模数m"}
        
        result_text += f"恢复的模数 m = {m_val}\n\n"
    
    if a_val is None:
        if len(y) < 3:
            return {'success': False, 'text': "恢复乘数a需要至少3个输出值"}
        
        a_val = recover_multiplier(y, m_val)
        if a_val is None:
            return {'success': False, 'text': "无法恢复乘数a\n\n可能原因:\n• 输出值有误\n• 模数m不正确"}
        
        result_text += f"恢复的乘数 a = {a_val}\n\n"
    
    if c_val is None:
        c_val = recover_increment(y, m_val, a_val)
        if c_val is None:
            return {'success': False, 'text': "无法恢复增量c"}
        
        result_text += f"恢复的增量 c = {c_val}\n\n"
    
    result_text += "验证:\n"
    result_text += f"LCG公式: X_{{n+1}} = ({a_val} * X_n + {c_val}) mod {m_val}\n\n"
    
    next_val = (a_val * y[-1] + c_val) % m_val
    result_text += f"下一个预测值: {next_val}"
    
    return {
        'success': True,
        'text': f"攻击成功!\n\n{result_text}",
        'm': m_val,
        'a': a_val,
        'c': c_val
    }
