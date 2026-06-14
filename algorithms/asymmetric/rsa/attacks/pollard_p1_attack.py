"""
Pollard p-1分解攻击模块
=======================

【攻击原理】
当p-1的所有素因子都很小（即p-1是B-光滑数）时，
可以使用Pollard p-1算法分解n。

算法基于费马小定理: a^(p-1) ≡ 1 (mod p)

如果p-1整除某个数M，则:
  a^M ≡ 1 (mod p)
因此:
  gcd(a^M - 1, n) 可能等于p

选择M = B!（B的阶乘），如果p-1的所有因子≤B，
则p-1 | M，从而可以分解n。

【适用条件】
1. p-1是B-光滑数（所有素因子≤B）
2. B不能太大，否则计算量过大

【攻击步骤】
1. 选择光滑界B
2. 计算 a = 2^(B!) mod n
3. 计算 d = gcd(a - 1, n)
4. 如果 1 < d < n，则d是p或q

【CTF例题】
已知: n（p-1光滑）
求: p, q

解法:
1. 选择适当的B值
2. 执行Pollard p-1算法

【参考】
- Pollard p-1分解
- 光滑数
- Williams p+1分解
"""

ATTACK_NAME = "Pollard p-1分解"
ATTACK_DESC = "p-1光滑时有效"
ATTACK_HINT = """【攻击说明】
当p-1的因子都比较小时有效。

输入参数:
- 模数n: 要分解的RSA模数
- 光滑界B: 搜索上限

原理: 若p-1是B-光滑数，则可分解n"""

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
        'name': 'B',
        'label': '光滑界 B',
        'type': 'number',
        'default': '100000',
        'placeholder': '光滑界B',
        'required': False
    }
]

import math


def attack(n, B='100000'):
    """
    执行Pollard p-1分解攻击
    
    参数:
        n: 要分解的模数
        B: 光滑界
    
    返回:
        str: 攻击结果
    """
    if not n:
        return {"success": False, "text": "请输入模数n"}
    
    try:
        n = int(n)
        B = int(B) if B else 100000
    except ValueError as ex:
        return {"success": False, "text": f"输入格式错误: {str(ex)}"}
    
    a = 2
    for j in range(2, B):
        a = pow(a, j, n)
        d = math.gcd(a - 1, n)
        if 1 < d < n:
            p, q = d, n // d
            phi = (p - 1) * (q - 1)
            text = f"Pollard p-1分解成功!\n\np = {p}\nq = {q}\n\nφ(n) = {phi}"
            return {"success": True, "text": text, "p": p, "q": q, "phi": phi}
    
    text = f"Pollard p-1分解失败\n\n已尝试到 B = {B}\n\n可能原因:\n• p-1没有足够小的因子\n• 建议增大B值或尝试其他方法"
    return {"success": False, "text": text}
