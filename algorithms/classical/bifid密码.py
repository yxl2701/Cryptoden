"""
Bifid密码加密模块
=================

【算法介绍】
Bifid密码由Felix Delastelle于1901年发明，是一种结合了Polybius方阵
和分数化（Fractionation）的古典密码。

【加密原理】
1. 使用5x5的Polybius方阵（I/J合并）
2. 将每个字母转换为行和列坐标
3. 将坐标按行分组，再按列读取
4. 将新的坐标对转换回字母

【示例】
密钥: KEY
明文: HELLO
密文: ...

【参数说明】
- key: 密钥，用于生成Polybius方阵
"""

ALGORITHM_NAME = "Bifid密码"
ALGORITHM_DESC = "Bifid密码，结合Polybius方阵和分数化的古典密码"


def _generate_polybius_square(key):
    """生成5x5 Polybius方阵"""
    key = key.upper()
    alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'  # 合并I/J
    used = set()
    square = []

    for c in key:
        if c not in used and c in alphabet:
            square.append(c)
            used.add(c)

    for c in alphabet:
        if c not in used:
            square.append(c)
            used.add(c)

    return square


def encrypt(plaintext, key=''):
    """
    Bifid密码加密

    参数:
        plaintext (str): 明文
        key (str): 密钥

    返回:
        str: 密文
    """
    square = _generate_polybius_square(key)
    # 构建字符到坐标的映射
    char_to_pos = {}
    for i, c in enumerate(square):
        row = i // 5
        col = i % 5
        char_to_pos[c] = (row, col)

    # 坐标到字符的映射
    pos_to_char = {i: c for i, c in enumerate(square)}

    # 处理明文
    plaintext = plaintext.upper().replace('J', 'I')
    rows = []
    cols = []

    for c in plaintext:
        if c in char_to_pos:
            r, col = char_to_pos[c]
            rows.append(r)
            cols.append(col)
        elif c == ' ':
            rows.append(' ')
            cols.append(' ')

    # 合并坐标：先所有行，再所有列
    combined = rows + cols

    # 每两个坐标一组，转换为字母
    result = []
    for i in range(0, len(combined), 2):
        if combined[i] == ' ':
            result.append(' ')
            continue
        if i + 1 < len(combined) and combined[i + 1] != ' ':
            idx = combined[i] * 5 + combined[i + 1]
            if idx < 25:
                result.append(pos_to_char[idx])
            else:
                result.append('?')
        elif i + 1 < len(combined):
            result.append('?')

    return ''.join(result)


def decrypt(ciphertext, key=''):
    """
    Bifid密码解密

    参数:
        ciphertext (str): 密文
        key (str): 密钥

    返回:
        str: 明文
    """
    square = _generate_polybius_square(key)
    char_to_pos = {}
    for i, c in enumerate(square):
        row = i // 5
        col = i % 5
        char_to_pos[c] = (row, col)

    pos_to_char = {i: c for i, c in enumerate(square)}

    ciphertext = ciphertext.upper().replace('J', 'I')

    # 获取所有坐标
    coords = []
    for c in ciphertext:
        if c in char_to_pos:
            r, col = char_to_pos[c]
            coords.append(r)
            coords.append(col)
        elif c == ' ':
            coords.append(' ')

    # 分离坐标：前半部分为行，后半部分为列
    mid = len(coords) // 2
    rows = coords[:mid]
    cols = coords[mid:]

    result = []
    for r, c in zip(rows, cols):
        if r == ' ' or c == ' ':
            result.append(' ')
            continue
        idx = r * 5 + c
        if idx < 25:
            result.append(pos_to_char[idx])
        else:
            result.append('?')

    return ''.join(result)