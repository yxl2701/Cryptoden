"""
已知因子分解攻击模块
====================

【攻击原理】
当已知RSA模数n的一个因子p或q时，可以直接计算所有RSA参数。

已知: n = p * q
可计算:
- q = n / p（或 p = n / q）
- φ(n) = (p-1) * (q-1)
- d = e^(-1) mod φ(n)（如果已知e）

【适用条件】
1. 已知p或q
2. 可选：已知公钥e以计算私钥d

【攻击步骤】
1. 验证p是n的因子
2. 计算 q = n / p
3. 计算 φ(n) = (p-1) * (q-1)
4. 如果已知e，计算 d = e^(-1) mod φ(n)

【CTF例题】
已知: n, p（或通过其他途径获得）
求: q, φ(n), d

解法:
1. q = n / p
2. φ(n) = (p-1) * (q-1)
3. d = mod_inverse(e, φ(n))

【参考】
- RSA基础
- 模逆计算
"""

ATTACK_NAME = "已知因子分解"
ATTACK_DESC = "已知p或q时直接计算"
ATTACK_HINT = """【攻击说明】
已知p或q时可直接计算所有RSA参数。

输入参数:
- 模数n: RSA模数
- 已知因子: p或q
- 公钥e: 可选，用于计算私钥d

输出: q, φ(n), 私钥d（如果提供e）"""

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
        'name': 'p',
        'label': '已知因子',
        'type': 'text',
        'default': '',
        'placeholder': '输入已知的p或q',
        'required': True
    },
    {
        'name': 'e',
        'label': '公钥 e (可选)',
        'type': 'text',
        'default': '',
        'placeholder': '输入公钥e以计算私钥d',
        'required': False
    }
]

import math

from algorithms.asymmetric.rsa.utils import mod_inverse, parse_input_value


def attack(n, p, e=''):
    """
    执行已知因子分解攻击
    
    参数:
        n: 模数
        p: 已知因子
        e: 公钥(可选)
    
    返回:
        dict: 攻击结果，包含 success, text, p, q, phi, d 等字段
    """
    if not n or not p:
        return {'success': False, 'text': "请输入模数n和已知因子"}
    
    try:
        n = parse_input_value(str(n))
        p = parse_input_value(str(p))
        if n is None or p is None:
            raise ValueError("n或p格式无效")
    except ValueError as ex:
        return {'success': False, 'text': f"输入格式错误: {str(ex)}"}
    
    if n % p != 0:
        return {'success': False, 'text': f"错误: {p} 不是 {n} 的因子"}
    
    q = n // p
    phi = (p - 1) * (q - 1)
    
    result_text = f"分解成功!\n\np = {p}\nq = {q}\n\nφ(n) = {phi}\n"
    result = {
        'success': True,
        'p': p,
        'q': q,
        'phi': phi
    }
    
    if e:
        try:
            e = parse_input_value(str(e))
            if e is None:
                raise ValueError("e格式无效")
            if math.gcd(e, phi) != 1:
                result_text += f"\n错误: e={e} 与 φ(n) 不互质"
            else:
                d = mod_inverse(e, phi)
                if d:
                    result_text += f"\n私钥 d = {d}\n公钥 e = {e}"
                    result['d'] = d
                    result['e'] = e
        except ValueError as ex:
            result_text += f"\n公钥e格式错误: {str(ex)}"
    
    result['text'] = result_text
    return result
