"""
ADFGVX密码加密模块
==================

【算法介绍】
ADFGVX密码是第一次世界大战期间德军使用的一种密码，
结合了替换密码（Polybius方阵）和换位密码（列换位）。
密码名来源于其使用的6个字母：A、D、F、G、V、X。

【加密原理】
1. 构建6x6 Polybius方阵，填入26个字母和10个数字
2. 将每个明文字符替换为方阵中的行列坐标（如 A=AA, 1=AD）
3. 对替换后的结果进行列换位加密

【解密原理】
1. 对密文进行列换位解密
2. 将每个坐标对还原为原始字符

【6x6 Polybius方阵示例】
     A D F G V X
   A 8 P 3 D 1 N
   D L T 4 O A H
   F 7 K B C 0 Z
   G 5 Q G 2 9 V
   V W F J 6 S Y
   X X U M E R I

【应用场景】
1. CTF密码题
2. 经典密码学教学

【参数说明】
- key: 换位密钥，用于列换位，默认为"GERMAN"
- keyword: 构建Polybius方阵的关键词，默认为"ADFGVX"
"""


def _build_polybius_square(keyword: str = "") -> list:
    """构建6x6 Polybius方阵"""
    chars = []
    seen = set()
    for c in (keyword.upper() + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"):
        if c not in seen and c.isalnum():
            chars.append(c)
            seen.add(c)

    square = []
    for i in range(6):
        row = []
        for j in range(6):
            idx = i * 6 + j
            if idx < len(chars):
                row.append(chars[idx])
            else:
                row.append('')
        square.append(row)
    return square


def _find_in_square(square, char) -> str:
    """在Polybius方阵中查找字符的位置"""
    labels = ['A', 'D', 'F', 'G', 'V', 'X']
    char = char.upper()
    for i, row in enumerate(square):
        for j, c in enumerate(row):
            if c == char:
                return labels[i] + labels[j]
    return ''


def _get_char_from_square(square, coord: str) -> str:
    """根据坐标从Polybius方阵获取字符"""
    labels = {'A': 0, 'D': 1, 'F': 2, 'G': 3, 'V': 4, 'X': 5}
    if len(coord) != 2:
        return ''
    i = labels.get(coord[0], -1)
    j = labels.get(coord[1], -1)
    if i >= 0 and j >= 0 and i < 6 and j < 6:
        return square[i][j]
    return ''


def _get_column_order(key: str) -> list:
    """根据密钥确定列读取顺序"""
    indexed = [(char, idx) for idx, char in enumerate(key)]
    indexed.sort(key=lambda x: (x[0], x[1]))
    return [idx for _, idx in indexed]


def _columnar_encrypt(text: str, key: str) -> str:
    """列换位加密：按行写入，按列顺序读取"""
    num_cols = len(key)
    num_rows = (len(text) + num_cols - 1) // num_cols

    # 按行填充矩阵
    matrix = [[''] * num_cols for _ in range(num_rows)]
    for i, char in enumerate(text):
        row = i // num_cols
        col = i % num_cols
        matrix[row][col] = char

    # 按列顺序读取
    col_order = _get_column_order(key)
    result = []
    for col in col_order:
        for row in range(num_rows):
            if matrix[row][col] != '':
                result.append(matrix[row][col])
    return ''.join(result)


def _columnar_decrypt(text: str, key: str) -> str:
    """列换位解密：按列顺序写入，按行读取"""
    num_cols = len(key)
    num_rows = (len(text) + num_cols - 1) // num_cols

    # 计算每列的字符数
    col_order = _get_column_order(key)
    col_lengths = [num_rows] * num_cols
    total_cells = num_rows * num_cols
    empty_cells = total_cells - len(text)
    # 最后一行不满，末尾列少一个字符（按自然列顺序）
    for i in range(empty_cells):
        col_lengths[num_cols - 1 - i] -= 1

    # 按列顺序填充密文到矩阵
    matrix = [[''] * num_cols for _ in range(num_rows)]
    idx = 0
    for col in col_order:
        for row in range(col_lengths[col]):
            if idx < len(text):
                matrix[row][col] = text[idx]
                idx += 1

    # 按行读取
    result = []
    for row in range(num_rows):
        for col in range(num_cols):
            if matrix[row][col] != '':
                result.append(matrix[row][col])
    return ''.join(result)


def encrypt(plaintext, key="GERMAN", keyword="ADFGVX"):
    """
    ADFGVX加密

    1. 用Polybius方阵将明文字符替换为坐标
    2. 用列换位加密坐标串

    参数:
        plaintext (str): 明文
        key (str): 列换位密钥
        keyword (str): 构建Polybius方阵的关键词

    返回:
        str: 密文（仅包含A、D、F、G、V、X）
    """
    text = plaintext.upper().replace(' ', '')
    square = _build_polybius_square(keyword)

    # 替换为坐标
    coords = []
    for char in text:
        coord = _find_in_square(square, char)
        if coord:
            coords.append(coord)

    coord_str = ''.join(coords)

    # 列换位加密
    return _columnar_encrypt(coord_str, key)


def decrypt(ciphertext, key="GERMAN", keyword="ADFGVX"):
    """
    ADFGVX解密

    1. 用列换位解密坐标串
    2. 将坐标对还原为原始字符

    参数:
        ciphertext (str): 密文（仅包含A、D、F、G、V、X）
        key (str): 列换位密钥
        keyword (str): 构建Polybius方阵的关键词

    返回:
        str: 明文
    """
    valid_chars = set('ADFGVX')
    text = ''.join(c for c in ciphertext.upper() if c in valid_chars)

    if len(text) % 2 != 0:
        return "错误: 密文长度必须为偶数（坐标对）"

    # 列换位解密
    transposed = _columnar_decrypt(text, key)

    # 坐标对还原
    square = _build_polybius_square(keyword)
    result = []
    for i in range(0, len(transposed), 2):
        coord = transposed[i:i+2]
        char = _get_char_from_square(square, coord)
        if char:
            result.append(char)

    return ''.join(result)