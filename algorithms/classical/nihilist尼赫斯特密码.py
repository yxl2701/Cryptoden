"""
尼赫斯特密码加密模块
===================

【算法介绍】
尼赫斯特密码（Nihilist Cipher）是一种结合了Polybius方阵
和加法运算的古典密码，由俄国民粹主义者（Nihilists）使用。

【加密原理】
1. 使用5x5的Polybius方阵（I/J合并）
2. 将明文和密钥分别转换为两位数坐标
3. 将明文的坐标与密钥的坐标相加（模100）
4. 得到密文数字序列

【示例】
密钥: KEY
明文: HELLO
密文: 数字序列

【参数说明】
- key: 密钥
"""

ALGORITHM_NAME = "尼赫斯特密码"
ALGORITHM_DESC = "Nihilist密码，Polybius方阵+加法运算的古典密码"


def _generate_polybius_square(key=''):
    """生成5x5 Polybius方阵"""
    key = key.upper()
    alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
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


def _char_to_coord(c, square):
    """将字符转换为两位数坐标（1-based）"""
    if c == 'J':
        c = 'I'
    idx = square.index(c) if c in square else -1
    if idx == -1:
        return None
    row = idx // 5 + 1
    col = idx % 5 + 1
    return row * 10 + col


def _coord_to_char(coord, square):
    """将两位数坐标转换为字符"""
    row = coord // 10 - 1
    col = coord % 10 - 1
    if row < 0 or row >= 5 or col < 0 or col >= 5:
        return None
    idx = row * 5 + col
    if idx < len(square):
        return square[idx]
    return None


def encrypt(plaintext, key=''):
    """
    尼赫斯特密码加密

    参数:
        plaintext (str): 明文
        key (str): 密钥

    返回:
        str: 数字序列密文，空格分隔
    """
    square = _generate_polybius_square()
    key_square = _generate_polybius_square(key)

    plaintext = plaintext.upper().replace('J', 'I').replace(' ', '')
    key = key.upper().replace('J', 'I').replace(' ', '')

    if not key:
        key = 'A'

    # 扩展密钥到明文长度
    extended_key = (key * (len(plaintext) // len(key) + 1))[:len(plaintext)]

    result = []
    for p, k in zip(plaintext, extended_key):
        p_coord = _char_to_coord(p, square)
        k_coord = _char_to_coord(k, key_square)
        if p_coord is not None and k_coord is not None:
            # 加法
            encrypted = (p_coord + k_coord) % 100
            result.append(str(encrypted).zfill(2))

    return ' '.join(result)


def decrypt(ciphertext, key=''):
    """
    尼赫斯特密码解密

    参数:
        ciphertext (str): 数字序列密文，空格分隔
        key (str): 密钥

    返回:
        str: 明文
    """
    square = _generate_polybius_square()
    key_square = _generate_polybius_square(key)

    key = key.upper().replace('J', 'I').replace(' ', '')
    if not key:
        key = 'A'

    # 解析数字
    numbers = [int(n) for n in ciphertext.replace(',', ' ').split() if n.strip().isdigit()]

    extended_key = (key * (len(numbers) // len(key) + 1))[:len(numbers)]

    result = []
    for n, k in zip(numbers, extended_key):
        k_coord = _char_to_coord(k, key_square)
        if k_coord is not None:
            # 减法
            decrypted = (n - k_coord) % 100
            c = _coord_to_char(decrypted, square)
            result.append(c if c else '?')

    return ''.join(result)