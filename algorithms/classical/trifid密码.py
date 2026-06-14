"""
Trifid密码加密模块
=================

【算法介绍】
Trifid密码由Felix Delastelle发明，是Bifid密码的三维扩展。
使用3x3x3的立方体（27个字符），将每个字母编码为三维坐标。

【加密原理】
1. 使用3x3x3的立方体，包含26个字母和1个额外字符
2. 将每个字母转换为三维坐标（层、行、列）
3. 将坐标按层-行-列分组，再按新顺序读取
4. 将新坐标转换回字母

【示例】
密钥: KEY
明文: HELLO
密文: ...

【参数说明】
- key: 密钥
"""

ALGORITHM_NAME = "Trifid密码"
ALGORITHM_DESC = "Trifid密码，Bifid的三维扩展，使用3x3x3立方体"


def _generate_cube(key=''):
    """生成3x3x3立方体（27个字符）"""
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ+'
    key = key.upper()
    used = set()
    cube = []

    for c in key:
        if c not in used and c in alphabet:
            cube.append(c)
            used.add(c)

    for c in alphabet:
        if c not in used:
            cube.append(c)
            used.add(c)

    return cube


def encrypt(plaintext, key='', period=3):
    """
    Trifid密码加密

    参数:
        plaintext (str): 明文
        key (str): 密钥
        period (int): 分组周期

    返回:
        str: 密文
    """
    cube = _generate_cube(key)
    char_to_pos = {}
    for i, c in enumerate(cube):
        layer = i // 9
        row = (i % 9) // 3
        col = i % 3
        char_to_pos[c] = (layer, row, col)

    pos_to_char = {i: c for i, c in enumerate(cube)}

    plaintext = plaintext.upper().replace(' ', '')
    if not plaintext:
        return ''

    # 每period个字符一组处理
    result = []
    for start in range(0, len(plaintext), period):
        group = plaintext[start:start + period]

        layers, rows, cols = [], [], []
        for c in group:
            if c in char_to_pos:
                l, r, co = char_to_pos[c]
                layers.append(l)
                rows.append(r)
                cols.append(co)
            else:
                layers.append(0)
                rows.append(0)
                cols.append(0)

        # 合并坐标：层+行+列
        combined = layers + rows + cols

        # 每3个坐标一组，转换为字母
        for i in range(0, len(combined), 3):
            if i + 2 < len(combined):
                idx = combined[i] * 9 + combined[i + 1] * 3 + combined[i + 2]
                if idx < 27:
                    result.append(pos_to_char[idx])
                else:
                    result.append('?')

    return ''.join(result)


def decrypt(ciphertext, key='', period=3):
    """
    Trifid密码解密

    参数:
        ciphertext (str): 密文
        key (str): 密钥
        period (int): 分组周期

    返回:
        str: 明文
    """
    cube = _generate_cube(key)
    char_to_pos = {}
    for i, c in enumerate(cube):
        layer = i // 9
        row = (i % 9) // 3
        col = i % 3
        char_to_pos[c] = (layer, row, col)

    pos_to_char = {i: c for i, c in enumerate(cube)}

    ciphertext = ciphertext.upper().replace(' ', '')
    if not ciphertext:
        return ''

    result = []
    for start in range(0, len(ciphertext), period):
        group = ciphertext[start:start + period]

        # 获取所有坐标
        coords = []
        for c in group:
            if c in char_to_pos:
                l, r, co = char_to_pos[c]
                coords.extend([l, r, co])

        # 分成三部分
        third = len(coords) // 3
        layers = coords[:third]
        rows = coords[third:2 * third]
        cols = coords[2 * third:]

        # 重组
        for l, r, c in zip(layers, rows, cols):
            idx = l * 9 + r * 3 + c
            if idx < 27:
                result.append(pos_to_char[idx])
            else:
                result.append('?')

    return ''.join(result)