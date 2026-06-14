"""
LSB Oracle攻击模块（奇偶Oracle攻击）
====================================

【攻击原理】
当存在一个Oracle可以返回密文解密后明文的最低位（奇偶性）时，
可以通过二分查找恢复明文。

原理:
- 如果 LSB(m) = 0，则 m 是偶数，即 m < n/2
- 如果 LSB(m) = 1，则 m 是奇数，即 m > n/2

通过构造 c' = c * 2^e mod n，解密后得到 m' = 2m mod n
- 如果 LSB(m') = 0，则 2m < n，即 m < n/2
- 如果 LSB(m') = 1，则 2m > n，即 m > n/2

重复这个过程可以逐步缩小m的范围。

【适用条件】
1. 存在返回明文LSB的Oracle
2. 已知密文c

【CTF例题】
已知: n, e, c, Oracle(c)返回解密后明文的LSB
求: 明文m

【参考】
- LSB Oracle攻击
- 奇偶Oracle攻击
- 二分查找
"""

ATTACK_NAME = "LSB Oracle攻击"
ATTACK_DESC = "利用奇偶Oracle恢复明文"
ATTACK_HINT = """【攻击说明】
利用返回明文最低位的Oracle进行二分查找。

输入参数:
- 模数n: RSA模数
- 公钥e: RSA公钥
- 密文c: 待解密的密文
- LSB序列: Oracle返回的LSB序列（0和1组成的字符串）

说明: 每次查询Oracle(c * 2^k mod n)得到一个LSB位
需要n位长度的LSB序列才能完全恢复明文"""

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
        'default': '65537',
        'placeholder': '输入公钥e',
        'required': True
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
        'name': 'lsb_sequence',
        'label': 'LSB序列',
        'type': 'textarea',
        'default': '',
        'placeholder': '输入LSB序列（0和1组成的字符串）',
        'required': True
    }
]

import math


def decode_plaintext(m):
    """将整数转换为明文"""
    if m == 0:
        return ""
    byte_length = (m.bit_length() + 7) // 8
    try:
        return m.to_bytes(byte_length, 'big').decode('utf-8', errors='replace')
    except:
        return f"(无法解码为UTF-8，十六进制: {hex(m)})"


def attack(n, e, c, lsb_sequence):
    """
    执行LSB Oracle攻击
    
    参数:
        n: 模数
        e: 公钥
        c: 密文
        lsb_sequence: LSB位序列字符串
    
    返回:
        dict: 攻击结果
    """
    if not n or not c or not lsb_sequence:
        return {'success': False, 'text': "请填写所有参数"}
    
    try:
        n = int(n)
        e = int(e) if e else 65537
        c = int(c)
    except ValueError as ex:
        return {'success': False, 'text': f"输入格式错误: {str(ex)}"}
    
    lsb_sequence = lsb_sequence.strip().replace(' ', '').replace('\n', '').replace(',', '')
    
    if not all(b in '01' for b in lsb_sequence):
        return {'success': False, 'text': "LSB序列只能包含0和1"}
    
    low = 0
    high = n
    
    c_current = c
    two_e = pow(2, e, n)
    
    for i, bit in enumerate(lsb_sequence):
        c_current = (c_current * two_e) % n
        
        if bit == '0':
            high = (low + high) // 2
        else:
            low = (low + high) // 2
        
        if high - low <= 1:
            break
    
    m = high
    
    result = decode_plaintext(m)
    
    return {
        'success': True,
        'text': f"攻击成功!\n\n使用 {min(len(lsb_sequence), i+1)} 位LSB\n明文(整数): {m}\n\n明文: {result}\n\n说明: 使用了{n.bit_length()}位中的{min(len(lsb_sequence), i+1)}位",
        'm': m
    }


def generate_lsb_query(c, k, e, n):
    """
    生成第k次查询的密文
    
    参数:
        c: 原始密文
        k: 查询次数
        e: 公钥
        n: 模数
    
    返回:
        查询密文
    """
    two_ek = pow(2, e * k, n)
    return (c * two_ek) % n
