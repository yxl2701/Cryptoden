"""
小指数广播攻击模块
==================

【攻击原理】
当同一明文m被多个不同的模数ni加密，但使用相同的小公钥e时：
- c1 = m^e mod n1
- c2 = m^e mod n2
- c3 = m^e mod n3
- ...

如果收集到e组密文，可以使用中国剩余定理(CRT)恢复 m^e，
然后开e次方根得到明文m。

【数学推导】
由中国剩余定理，当n1, n2, ..., ne两两互质时：
  M = m^e mod (n1*n2*...*ne)

由于 m < ni，所以 m^e < n1*n2*...*ne
因此 M = m^e（无取模）

然后 m = M^(1/e)

【适用条件】
1. 相同的小公钥e
2. 不同的模数n（两两互质）
3. 至少e组密文
4. 同一明文被多次加密

【CTF例题】
已知: e=3, (n1,c1), (n2,c2), (n3,c3)
求: 明文m

解法:
1. 用CRT计算 M = m^3 mod (n1*n2*n3)
2. 由于 m^3 < n1*n2*n3，所以 M = m^3
3. m = cbrt(M)

【参考】
- 中国剩余定理(CRT)
- Håstad广播攻击
"""

ATTACK_NAME = "小指数广播攻击"
ATTACK_DESC = "e很小且多组密文时恢复明文"
ATTACK_HINT = """【攻击说明】
同一明文用相同小e但不同n加密时可恢复明文。

输入格式（多组数据）:
- 用分号分隔: n1,e,c1; n2,e,c2; n3,e,c3
- 或换行分隔，每行一组

条件:
- 所有公钥e必须相同
- 至少需要e组密文"""

INPUT_FIELDS = [
    {
        'name': 'data_groups',
        'label': '密文组',
        'type': 'textarea',
        'default': '',
        'placeholder': 'n1,e,c1; n2,e,c2; n3,e,c3\n或每行一组',
        'required': True
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


def attack(data_groups):
    """
    执行小指数广播攻击
    
    参数:
        data_groups: 多组数据字符串，格式为 n,e,c 用换行或分号分隔
    
    返回:
        dict: 攻击结果
    """
    if not data_groups or not data_groups.strip():
        return {'success': False, 'text': "请输入攻击参数"}
    
    input_text = data_groups.strip()
    
    if ';' in input_text:
        lines = [l.strip() for l in input_text.split(';') if l.strip()]
    else:
        lines = [l.strip() for l in input_text.split('\n') if l.strip()]
    
    if len(lines) < 2:
        return {'success': False, 'text': "需要至少2组密文进行广播攻击"}
    
    data = []
    for i, line in enumerate(lines):
        parts = [p.strip() for p in line.replace(',', ' ').split() if p.strip()]
        if len(parts) >= 3:
            try:
                n = int(parts[0])
                e = int(parts[1])
                c = int(parts[2])
                data.append((n, e, c))
            except ValueError as ex:
                return {'success': False, 'text': f"第{i+1}组数据格式错误: {str(ex)}"}
        else:
            return {'success': False, 'text': f"第{i+1}组数据格式错误，需要 n, e, c"}
    
    e = data[0][1]
    for j, (_, ei, _) in enumerate(data):
        if ei != e:
            return {'success': False, 'text': f"所有公钥指数e必须相同\n第1组: e={e}, 第{j+1}组: e={ei}"}
    
    n_list = [d[0] for d in data]
    c_list = [d[2] for d in data]
    
    N = 1
    for n in n_list:
        N *= n
    
    m_cubed = 0
    for i, c in enumerate(c_list):
        Ni = N // n_list[i]
        _, Mi, _ = extended_gcd(Ni, n_list[i])
        m_cubed += c * Mi * Ni
    
    m_cubed = m_cubed % N
    
    m = integer_nth_root(m_cubed, e)
    
    if m is not None:
        result = decode_plaintext(m)
        return {
            'success': True,
            'm': str(m),
            'plaintext': result,
            'text': f"攻击成功!\n\n明文(整数): {m}\n\n明文: {result}"
        }
    else:
        return {
            'success': False,
            'text': f"无法计算{e}次根\n\n可能原因:\n• 密文组数不足\n• 数据有误\n• 明文可能需要更多密文组"
        }
