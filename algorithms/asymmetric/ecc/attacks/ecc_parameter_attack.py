"""
ECC参数恢复攻击模块
===================

【攻击原理】
椭圆曲线方程: y² = x³ + ax + b (mod p)

当已知曲线上的两个点时，可以通过解方程组恢复参数a和b。

设点 P1(x1, y1) 和 P2(x2, y2) 在曲线上：
- y1² = x1³ + a*x1 + b (mod p)
- y2² = x2³ + a*x2 + b (mod p)

两式相减：
- y1² - y2² = x1³ - x2³ + a(x1 - x2) (mod p)
- a = (y1² - y2² - x1³ + x2³) / (x1 - x2) (mod p)

然后：
- b = y1² - x1³ - a*x1 (mod p)

【适用条件】
1. 已知椭圆曲线上的两个不同点
2. 两点x坐标不同

【CTF例题】
已知: p, 点P1(x1, y1), 点P2(x2, y2)
求: 曲线参数a, b

【参考】
- 椭圆曲线基础
- 参数恢复
"""

ATTACK_NAME = "ECC参数恢复"
ATTACK_DESC = "从已知点恢复曲线参数"
ATTACK_HINT = """【攻击说明】
从椭圆曲线上的两个已知点恢复曲线参数a和b。

输入参数:
- 素数p: 曲线所在有限域的素数
- 点1坐标: x1, y1
- 点2坐标: x2, y2

条件: 两点的x坐标必须不同"""

INPUT_FIELDS = [
    {
        'name': 'p',
        'label': '素数 p',
        'type': 'text',
        'default': '',
        'placeholder': '输入素数p',
        'required': True
    },
    {
        'name': 'x1',
        'label': '点1 x坐标',
        'type': 'text',
        'default': '',
        'placeholder': 'x1',
        'required': True
    },
    {
        'name': 'y1',
        'label': '点1 y坐标',
        'type': 'text',
        'default': '',
        'placeholder': 'y1',
        'required': True
    },
    {
        'name': 'x2',
        'label': '点2 x坐标',
        'type': 'text',
        'default': '',
        'placeholder': 'x2',
        'required': True
    },
    {
        'name': 'y2',
        'label': '点2 y坐标',
        'type': 'text',
        'default': '',
        'placeholder': 'y2',
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
    gcd, x, _ = extended_gcd(a % n, n)
    if gcd != 1:
        return None
    return (x % n + n) % n


def attack(p, x1, y1, x2, y2):
    """
    执行ECC参数恢复攻击
    
    参数:
        p: 素数
        x1, y1: 点1坐标
        x2, y2: 点2坐标
    
    返回:
        dict: 攻击结果
    """
    if not all([p, x1, y1, x2, y2]):
        return {'success': False, 'text': "请填写所有参数"}
    
    try:
        p = int(p)
        x1 = int(x1)
        y1 = int(y1)
        x2 = int(x2)
        y2 = int(y2)
    except ValueError as ex:
        return {'success': False, 'text': f"输入格式错误: {str(ex)}"}
    
    if x1 == x2:
        return {'success': False, 'text': "两点的x坐标不能相同"}
    
    try:
        y1_sq = pow(y1, 2, p)
        y2_sq = pow(y2, 2, p)
        x1_cu = pow(x1, 3, p)
        x2_cu = pow(x2, 3, p)
        
        denom = (x1 - x2) % p
        denom_inv = mod_inverse(denom, p)
        
        if denom_inv is None:
            return {'success': False, 'text': f"无法计算模逆，x1-x2={denom}与p={p}不互质"}
        
        numer = (y1_sq - y2_sq - x1_cu + x2_cu) % p
        a = (numer * denom_inv) % p
        
        b = (y1_sq - x1_cu - a * x1) % p
        
        result_text = f"椭圆曲线方程: y² = x³ + {a}x + {b} (mod {p})\n\n"
        result_text += f"参数 a = {a}\n"
        result_text += f"参数 b = {b}\n\n"
        
        result_text += "验证:\n"
        lhs1 = pow(y1, 2, p)
        rhs1 = (pow(x1, 3, p) + a * x1 + b) % p
        lhs2 = pow(y2, 2, p)
        rhs2 = (pow(x2, 3, p) + a * x2 + b) % p
        
        result_text += f"点1验证: y1² mod p = {lhs1}\n"
        result_text += f"         x1³ + ax1 + b mod p = {rhs1}\n"
        result_text += f"         匹配: {lhs1 == rhs1}\n\n"
        result_text += f"点2验证: y2² mod p = {lhs2}\n"
        result_text += f"         x2³ + ax2 + b mod p = {rhs2}\n"
        result_text += f"         匹配: {lhs2 == rhs2}"
        
        return {
            'success': True,
            'text': f"攻击成功!\n\n{result_text}",
            'a': a,
            'b': b
        }
        
    except Exception as ex:
        return {'success': False, 'text': f"计算错误: {str(ex)}"}
