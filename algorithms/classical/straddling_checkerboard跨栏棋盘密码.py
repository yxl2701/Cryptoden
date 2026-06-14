"""
跨栏棋盘密码加密模块
===================

【算法介绍】
跨栏棋盘密码（Straddling Checkerboard）是一种将字母映射为
数字的密码，通过将常用字母放在同一行以减少编码长度。

【加密原理】
1. 创建3行棋盘：第1行有多个数字槽位，第2-3行有完整的0-9
2. 第一行放置常用字母，第二行放置剩余字母
3. 第一行字母直接用数字编码，第二行用两位数字（首位为行标识）
4. 常用于Nihilist密码和One-Time Pad

【示例】
密钥: KEY
明文: HELLO
密文: 数字序列

【参数说明】
- key: 密钥，用于排列字母顺序
"""

ALGORITHM_NAME = "跨栏棋盘密码"
ALGORITHM_DESC = "Straddling Checkerboard，字母到数字的映射密码"


def _build_checkerboard(key=''):
    """构建跨栏棋盘

    返回 (board, encode_map, decode_map)
    board: 棋盘字典 {行: {数字: 字母}}
    encode_map: {字母: 编码}
    decode_map: {编码: 字母}
    """
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    key = key.upper()

    # 第一行放8个字母（数字0-7）
    # 第2-3行放剩余字母（用8和9作为行标识符）
    first_row_chars = []

    # 从密钥中取前8个不重复字母
    used = set()
    for c in key:
        if c in alphabet and c not in used:
            first_row_chars.append(c)
            used.add(c)
            if len(first_row_chars) >= 8:
                break

    # 补足到8个
    for c in alphabet:
        if c not in used and len(first_row_chars) < 8:
            first_row_chars.append(c)
            used.add(c)

    # 剩余字母分为两行
    remaining = [c for c in alphabet if c not in used]
    second_row = remaining[:9]  # 行标识8
    third_row = remaining[9:]   # 行标识9

    encode_map = {}
    decode_map = {}

    # 第一行：数字0-7
    for i, c in enumerate(first_row_chars):
        code = str(i)
        encode_map[c] = code
        decode_map[code] = c

    # 第二行：8 + 数字0-8
    for i, c in enumerate(second_row):
        code = f'8{i}'
        encode_map[c] = code
        decode_map[code] = c

    # 第三行：9 + 数字0-8
    for i, c in enumerate(third_row):
        code = f'9{i}'
        encode_map[c] = code
        decode_map[code] = c

    return encode_map, decode_map


def encrypt(plaintext, key=''):
    """
    跨栏棋盘密码加密

    参数:
        plaintext (str): 明文
        key (str): 密钥

    返回:
        str: 数字序列
    """
    encode_map, _ = _build_checkerboard(key)
    plaintext = plaintext.upper().replace(' ', '')

    result = []
    for c in plaintext:
        if c in encode_map:
            result.append(encode_map[c])
        else:
            result.append('?')

    return ' '.join(result)


def decrypt(ciphertext, key=''):
    """
    跨栏棋盘密码解密

    参数:
        ciphertext (str): 数字序列（空格可省略）
        key (str): 密钥

    返回:
        str: 明文
    """
    _, decode_map = _build_checkerboard(key)

    # 移除空格
    digits = ciphertext.replace(' ', '')

    result = []
    i = 0
    while i < len(digits):
        if digits[i] in ('8', '9'):
            # 两位编码
            code = digits[i:i+2]
            if code in decode_map:
                result.append(decode_map[code])
            else:
                result.append('?')
            i += 2
        else:
            # 一位编码
            code = digits[i]
            if code in decode_map:
                result.append(decode_map[code])
            else:
                result.append('?')
            i += 1

    return ''.join(result)