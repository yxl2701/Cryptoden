"""
低加密指数攻击模块
==================

【攻击原理】
当RSA加密使用的公钥指数e很小（如e=3），且明文m满足 m^e < n 时，
密文 c = m^e mod n 实际上就等于 m^e（因为没有取模）。
此时可以直接对密文开e次方根得到明文。

【适用条件】
1. 公钥指数e很小（通常e=3, 5, 7, 17等）
2. 明文m较小，满足 m^e < n
3. 或者 m^e 略大于 n，但满足 c + k*n 是完全e次方数

【攻击步骤】
1. 首先尝试直接对c开e次方根
2. 如果不是完全e次方，尝试 c + k*n (k=1,2,3,...)
3. 如果给定e失败，可自动尝试其他小e值（3, 5, 7, 11, 13, 17...）
4. 找到完全e次方数后，开方得到明文

【CTF例题】
已知: n, e=3, c
当 m^3 < n 时，直接计算 m = cbrt(c)

【参考】
- RSA低加密指数攻击
- Coppersmith攻击
"""

ATTACK_NAME = "低加密指数攻击"
ATTACK_DESC = "e=3且m^3<n时直接开立方"
ATTACK_HINT = """【攻击说明】
当e很小（如3）且明文较小时，可直接计算明文。

输入参数:
- 模数n: RSA模数
- 公钥e: 通常为3（留空自动尝试小e值）
- 密文c: 待解密的密文
- 最大k值: c + k*n 的最大k值
- 最大e值: 自动尝试e时的上限

原理: 若 m^e < n，则 c = m^e，直接开e次方即可"""

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
        'default': '3',
        'placeholder': '通常为3，留空自动尝试',
        'required': False
    },
    {
        'name': 'c',
        'label': '密文 c',
        'type': 'text',
        'default': '',
        'placeholder': '输入密文c',
        'required': True
    },
    {
        'name': 'max_k',
        'label': '最大k值',
        'type': 'number',
        'default': '1000',
        'placeholder': 'c+k*n的最大k值',
        'required': False
    },
    {
        'name': 'max_e',
        'label': '最大e值',
        'type': 'number',
        'default': '257',
        'placeholder': '自动尝试e时的上限',
        'required': False
    }
]

import math


def integer_nth_root(x, n):
    """计算整数n次根"""
    if x < 0:
        return None
    if x == 0:
        return 0
    
    low, high = 0, x
    while low < high:
        mid = (low + high + 1) // 2
        if mid ** n <= x:
            low = mid
        else:
            high = mid - 1
    
    if low ** n == x:
        return low
    return None


def decode_plaintext(m):
    """将整数转换为明文"""
    if m == 0:
        return ""
    byte_length = (m.bit_length() + 7) // 8
    try:
        return m.to_bytes(byte_length, 'big').decode('utf-8', errors='replace')
    except:
        return f"(无法解码为UTF-8，十六进制: {hex(m)})"


def try_attack_with_e(n, e, c, max_k):
    """尝试用指定的e进行攻击"""
    m = integer_nth_root(c, e)
    
    if m is not None and pow(m, e) == c:
        return m, 0, "direct"
    
    for k in range(1, max_k + 1):
        m_cubed = c + k * n
        m = integer_nth_root(m_cubed, e)
        if m is not None and pow(m, e) == m_cubed:
            return m, k, "extended"
    
    return None, 0, None


def attack(n, e='', c='', max_k='1000', max_e='257'):
    """
    执行低加密指数攻击
    
    参数:
        n: 模数
        e: 公钥指数（留空自动尝试小e值）
        c: 密文
        max_k: c + k*n 的最大k值
        max_e: 自动尝试e时的上限
    
    返回:
        str: 攻击结果
    """
    if not n or not c:
        return {"success": False, "text": "请填写模数n和密文c"}
    
    try:
        n = int(n)
        c = int(c)
        max_k = int(max_k) if max_k else 1000
        max_e = int(max_e) if max_e else 257
    except ValueError as ex:
        return {"success": False, "text": f"输入格式错误: {str(ex)}"}
    
    small_primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 
                    53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 
                    107, 109, 113, 127, 131, 137, 139, 149, 151, 157,
                    163, 167, 173, 179, 181, 191, 193, 197, 199, 211,
                    223, 227, 229, 233, 239, 241, 251, 257]
    
    e_values_to_try = []
    
    if e and str(e).strip():
        try:
            given_e = int(e)
            if given_e > 0:
                e_values_to_try.append(given_e)
        except ValueError:
            pass
    
    for p in small_primes:
        if p <= max_e and p not in e_values_to_try:
            e_values_to_try.append(p)
    
    e_values_to_try.sort()
    
    results = []
    successful_attacks = []
    
    for current_e in e_values_to_try:
        m, k, method = try_attack_with_e(n, current_e, c, max_k)
        
        if m is not None:
            result = decode_plaintext(m)
            successful_attacks.append({
                'e': current_e,
                'm': m,
                'k': k,
                'method': method,
                'plaintext': result
            })
            
            if method == "direct":
                text = (
                    f"攻击成功!\n\n"
                    f"使用 e = {current_e}\n"
                    f"明文(整数): {m}\n\n"
                    f"明文: {result}\n\n"
                    f"说明: m^{current_e} < n，直接开{current_e}次方得到明文"
                )
                return {"success": True, "text": text, "m": m, "plaintext": result}
    
    if successful_attacks:
        best = successful_attacks[0]
        result = decode_plaintext(best['m'])
        
        if best['method'] == "direct":
            text = (
                f"攻击成功!\n\n"
                f"使用 e = {best['e']}\n"
                f"明文(整数): {best['m']}\n\n"
                f"明文: {result}\n\n"
                f"说明: m^{best['e']} < n，直接开{best['e']}次方得到明文"
            )
        else:
            text = (
                f"攻击成功!\n\n"
                f"使用 e = {best['e']}\n"
                f"明文(整数): {best['m']}\n\n"
                f"明文: {result}\n\n"
                f"说明: c + {best['k']}*n 开{best['e']}次方得到明文"
            )
        return {"success": True, "text": text, "m": best['m'], "plaintext": result}
    
    text = (
        f"低加密指数攻击失败\n\n"
        f"已尝试:\n"
        f"• e值范围: {e_values_to_try[0]} ~ {e_values_to_try[-1]}\n"
        f"• k值范围: 0 ~ {max_k}\n\n"
        f"可能原因:\n"
        f"• 明文m太大，不满足 m^e < n\n"
        f"• 需要更大的k值或e值\n"
        f"• 建议尝试广播攻击或其他方法"
    )
    return {"success": False, "text": text}
