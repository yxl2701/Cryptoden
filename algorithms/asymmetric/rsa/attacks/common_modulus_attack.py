"""
共模攻击模块
============

【攻击原理】
当同一明文m被两个不同的公钥(e1, e2)加密，但使用相同的模数n时：
- c1 = m^e1 mod n
- c2 = m^e2 mod n

如果gcd(e1, e2) = 1，可以使用扩展欧几里得算法恢复明文。

【数学推导】
由扩展欧几里得算法，存在s1, s2使得：
  s1*e1 + s2*e2 = gcd(e1,e2) = 1

则：
  m = c1^s1 * c2^s2 mod n

【适用条件】
1. 相同的模数n
2. 不同的公钥e1, e2
3. e1和e2互质（gcd(e1,e2)=1）
4. 同一明文被两个公钥加密

【CTF例题】
已知: n, e1, c1, e2, c2
求: 明文m

解法:
1. 验证gcd(e1,e2)=1
2. 用扩展欧几里得求s1, s2
3. 计算 m = c1^s1 * c2^s2 mod n

【参考】
- RSA共模攻击
- 扩展欧几里得算法
"""

ATTACK_NAME = "共模攻击"
ATTACK_DESC = "相同n不同e时恢复明文"
ATTACK_HINT = """【攻击说明】
同一明文用相同n但不同e加密时可恢复明文。

输入参数:
- 模数n: 公共模数
- 公钥e1: 第一个公钥
- 密文c1: 第一个密文
- 公钥e2: 第二个公钥
- 密文c2: 第二个密文

条件: e1和e2必须互质"""

INPUT_FIELDS = [
    {
        'name': 'n',
        'label': '模数 n',
        'type': 'text',
        'default': '',
        'placeholder': '公共模数n',
        'required': True
    },
    {
        'name': 'e1',
        'label': '公钥 e1',
        'type': 'text',
        'default': '',
        'placeholder': '第一个公钥e1',
        'required': True
    },
    {
        'name': 'c1',
        'label': '密文 c1',
        'type': 'text',
        'default': '',
        'placeholder': '第一个密文c1',
        'required': True
    },
    {
        'name': 'e2',
        'label': '公钥 e2',
        'type': 'text',
        'default': '',
        'placeholder': '第二个公钥e2',
        'required': True
    },
    {
        'name': 'c2',
        'label': '密文 c2',
        'type': 'text',
        'default': '',
        'placeholder': '第二个密文c2',
        'required': True
    }
]

import math

from algorithms.asymmetric.rsa.utils import decode_plaintext, extended_gcd, parse_input_value


def attack(n, e1, c1, e2, c2):
    """
    执行共模攻击
    
    参数:
        n: 公共模数
        e1: 第一个公钥
        c1: 第一个密文
        e2: 第二个公钥
        c2: 第二个密文
    
    返回:
        dict: 攻击结果
    """
    if not all([n, e1, c1, e2, c2]):
        return {'success': False, 'text': "请填写所有参数"}
    
    try:
        n = parse_input_value(str(n))
        e1 = parse_input_value(str(e1))
        c1 = parse_input_value(str(c1))
        e2 = parse_input_value(str(e2))
        c2 = parse_input_value(str(c2))
        if None in (n, e1, c1, e2, c2):
            raise ValueError("存在格式无效的参数")
    except ValueError as ex:
        return {'success': False, 'text': f"输入格式错误: {str(ex)}"}
    
    g = math.gcd(e1, e2)
    if g != 1:
        return {'success': False, 'text': f"e1和e2不互质\nGCD(e1,e2) = {g}\n\n可尝试用g作为指数计算"}
    
    _, s1, s2 = extended_gcd(e1, e2)
    
    try:
        if s1 < 0:
            c1_inv = pow(c1, -1, n)
            m = (pow(c2, s2, n) * pow(c1_inv, -s1, n)) % n
        elif s2 < 0:
            c2_inv = pow(c2, -1, n)
            m = (pow(c1, s1, n) * pow(c2_inv, -s2, n)) % n
        else:
            m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
    except ValueError as ex:
        return {'success': False, 'text': f"攻击失败: 密文与n不互质，无法求逆 ({str(ex)})"}
    
    result = decode_plaintext(m)
    
    return {
        'success': True,
        'text': f"攻击成功!\n\n明文(整数): {m}\n\n明文: {result}",
        'm': m
    }
