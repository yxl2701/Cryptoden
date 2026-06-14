"""
Williams p+1分解攻击模块
========================

【攻击原理】
当p+1的所有素因子都很小（即p+1是B-光滑数）时，
可以使用Williams p+1算法分解n。

这是Pollard p-1算法的变体，利用Lucas序列的性质。

算法基于Lucas序列:
  V_0 = 2, V_1 = P, V_n = P*V_{n-1} - V_{n-2}

如果p+1整除某个数M，则:
  V_M ≡ 2 (mod p)
因此:
  gcd(V_M - 2, n) 可能等于p

【适用条件】
1. p+1是B-光滑数（所有素因子≤B）
2. B不能太大，否则计算量过大

【攻击步骤】
1. 选择光滑界B
2. 对不同的起始值计算Lucas序列
3. 计算 d = gcd(V - 2, n)
4. 如果 1 < d < n，则d是p或q

【CTF例题】
已知: n（p+1光滑）
求: p, q

解法:
1. 选择适当的B值
2. 执行Williams p+1算法

【参考】
- Williams p+1分解
- Lucas序列
- Pollard p-1分解
"""

ATTACK_NAME = "Williams p+1分解"
ATTACK_DESC = "p+1光滑时有效"
ATTACK_HINT = """【攻击说明】
当p+1的因子都比较小时有效。

输入参数:
- 模数n: 要分解的RSA模数
- 光滑界B: 搜索上限

原理: 若p+1是B-光滑数，则可分解n"""

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
    执行Williams p+1分解攻击
    
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
    
    for start in [3, 5, 7, 11, 13]:
        v = start
        for j in range(2, B):
            v = pow(v, j, n)
            v = (pow(v, 2, n) - 2) % n
            
            d = math.gcd(v - 2, n)
            if 1 < d < n:
                p, q = d, n // d
                phi = (p - 1) * (q - 1)
                text = f"Williams p+1分解成功!\n\np = {p}\nq = {q}\n\nφ(n) = {phi}"
                return {"success": True, "text": text, "p": p, "q": q, "phi": phi}
    
    text = f"Williams p+1分解失败\n\n已尝试到 B = {B}\n\n可能原因:\n• p+1没有足够小的因子\n• 建议增大B值或尝试其他方法"
    return {"success": False, "text": text}
