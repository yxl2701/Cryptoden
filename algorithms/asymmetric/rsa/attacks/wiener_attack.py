"""
Wiener攻击模块
==============

【攻击原理】
Wiener攻击是一种针对RSA的低解密指数攻击。当私钥d较小时，可以通过连分数展开恢复私钥。

数学基础：
- RSA中: e * d ≡ 1 (mod φ(n))
- 即: e * d = k * φ(n) + 1，其中k为某个正整数
- 因此: e/n ≈ k/d (当d较小时)

连分数展开：
- 对e/n进行连分数展开，得到渐近分数序列
- 如果d < N^0.25，则k/d必然出现在渐近分数中
- 通过验证每个渐近分数k/d，可以找到正确的私钥d

【攻击条件】
- 私钥d < N^0.25 (N的四次方根)
- 公钥e较大(通常接近N)

【攻击步骤】
1. 计算e/n的连分数展开
2. 遍历渐近分数k/d
3. 对每个k/d，计算φ(n) = (e*d - 1) / k
4. 由φ(n)和n求解p和q
5. 验证p*q = n

【时间复杂度】
O(log n)，非常高效

【参考文献】
Wiener, M. (1990). "Cryptanalysis of Short RSA Secret Exponents"
"""

ATTACK_NAME = "Wiener攻击"
ATTACK_DESC = "当私钥d较小时恢复私钥(d < N^0.25)"
ATTACK_HINT = "适用于e很大且d很小的情况，d < N^0.25时有效"

INPUT_FIELDS = [
    {
        'name': 'n',
        'label': '模数 N',
        'type': 'text',
        'placeholder': '输入模数N',
        'default': ''
    },
    {
        'name': 'e',
        'label': '公钥指数 e',
        'type': 'text',
        'placeholder': '输入公钥指数e',
        'default': ''
    },
    {
        'name': 'c',
        'label': '密文 c（可选）',
        'type': 'text',
        'placeholder': '输入密文c（可选，用于解密）',
        'default': ''
    }
]

import math

def continued_fraction(num, den):
    """计算连分数"""
    cf = []
    while den:
        q = num // den
        cf.append(q)
        num, den = den, num - q * den
    return cf


def convergents(cf):
    """计算渐近分数，返回(分子k, 分母d)"""
    n0, n1 = 0, 1
    d0, d1 = 1, 0
    for q in cf:
        n2 = q * n1 + n0
        d2 = q * d1 + d0
        yield n2, d2
        n0, n1 = n1, n2
        d0, d1 = d1, d2


def wiener_attack(e, n):
    """
    Wiener攻击核心实现
    :param e: 公钥指数
    :param n: 模数
    :return: (d, p, q) 或 None
    """
    cf = continued_fraction(e, n)
    
    for k, d in convergents(cf):
        if k == 0:
            continue
        
        # 检查 (e*d - 1) 是否能被 k 整除
        if (e * d - 1) % k != 0:
            continue
        
        phi = (e * d - 1) // k
        if phi <= 0:
            continue
        
        # p + q = n - phi + 1
        b = n - phi + 1
        # 判别式 = (p+q)^2 - 4*p*q = b^2 - 4n
        delta = b * b - 4 * n
        
        if delta >= 0:
            sqrt_delta = math.isqrt(delta)
            if sqrt_delta * sqrt_delta == delta:
                p = (b + sqrt_delta) // 2
                q = (b - sqrt_delta) // 2
                if p * q == n and p > 1 and q > 1:
                    return d, p, q
    
    return None


def attack(n: str, e: str, c: str = "", **kwargs) -> dict:
    """
    执行Wiener攻击
    
    参数:
        n: 模数
        e: 公钥指数
        c: 密文（可选）
        
    返回:
        攻击结果字典
    """
    if not n or not e:
        return {'success': False, 'text': '请填写模数N和公钥指数e'}
    
    try:
        n_val = int(n, 16) if n.startswith('0x') or n.startswith('0X') else int(n)
        e_val = int(e, 16) if e.startswith('0x') or e.startswith('0X') else int(e)
        c_val = int(c, 16) if c and (c.startswith('0x') or c.startswith('0X')) else int(c) if c else 0
    except ValueError as ex:
        return {'success': False, 'text': f'参数解析错误: {str(ex)}'}
    
    result = wiener_attack(e_val, n_val)
    
    if result:
        d, p, q = result
        phi = (p - 1) * (q - 1)
        
        text = f"Wiener攻击成功!\n\n私钥 d = {d}\n\np = {p}\nq = {q}\n\nφ(n) = {phi}"
        
        response = {
            'success': True,
            'd': str(d),
            'p': str(p),
            'q': str(q),
            'phi': str(phi),
            'text': text
        }
        
        if c_val:
            m = pow(c_val, d, n_val)
            response['m'] = str(m)
            
            try:
                m_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
                plaintext = m_bytes.decode('utf-8', errors='replace')
                response['plaintext'] = plaintext
                response['text'] += f"\n\n明文(整数) = {m}\n明文(文本) = {plaintext}"
            except:
                response['text'] += f"\n\n明文(整数) = {m}"
        
        return response
    else:
        return {
            'success': False,
            'text': 'Wiener攻击失败\n\n可能原因:\n1. 私钥d不够小 (需要 d < N^0.25)\n2. e/N的连分数展开中没有正确的渐近分数\n\nWiener攻击仅在 d < N^0.25 时有效'
        }
