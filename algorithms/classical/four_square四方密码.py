"""
四方密码加密模块
================

【算法介绍】
四方密码（Four-Square Cipher）由Felix Delastelle发明，
使用4个5x5的Polybius方阵，将明文中的字母对加密。

【加密原理】
1. 四个方阵：左上、右上、左下、右下
2. 左上和右下为明文字母表，右上和左下由密钥生成
3. 每次处理两个字母，在左上和右下找到它们的位置
4. 取右上和左下对应位置的字母作为密文

【示例】
密钥1: KEY
密钥2: WORD
明文: HELLO
密文: ...

【参数说明】
- key1: 第一个密钥
- key2: 第二个密钥
"""

ALGORITHM_NAME = "四方密码"
ALGORITHM_DESC = "Four-Square密码，使用四个Polybius方阵的古典密码"


def _generate_square(key):
    """生成5x5 Polybius方阵"""
    key = key.upper()
    alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
    used = set()
    result = []

    for c in key:
        if c not in used and c in alphabet:
            result.append(c)
            used.add(c)

    for c in alphabet:
        if c not in used:
            result.append(c)
            used.add(c)

    return result


def _build_pos_map(square):
    """构建字符到位置的映射"""
    return {c: (i // 5, i % 5) for i, c in enumerate(square)}


def _build_char_map(square):
    """构建位置到字符的映射"""
    return {i: c for i, c in enumerate(square)}


def encrypt(plaintext, key1='', key2=''):
    """
    四方密码加密

    参数:
        plaintext (str): 明文
        key1 (str): 第一个密钥
        key2 (str): 第二个密钥

    返回:
        str: 密文
    """
    # 四个方阵
    square1 = _generate_square('')  # 标准字母表
    square2 = _generate_square(key1)  # 右上
    square3 = _generate_square(key2)  # 左下
    square4 = _generate_square('')  # 标准字母表

    pos1 = _build_pos_map(square1)
    pos4 = _build_pos_map(square4)
    char2 = _build_char_map(square2)
    char3 = _build_char_map(square3)

    plaintext = plaintext.upper().replace('J', 'I').replace(' ', '')
    # 如果长度为奇数，补X
    if len(plaintext) % 2 == 1:
        plaintext += 'X'

    result = []
    for i in range(0, len(plaintext), 2):
        a, b = plaintext[i], plaintext[i + 1]
        if a not in pos1 or b not in pos4:
            result.extend([a, b])
            continue

        r1, c1 = pos1[a]
        r2, c2 = pos4[b]

        # 取右上对应行、左下对应列
        idx_a = r1 * 5 + c2  # 右上(r1, c2)
        idx_b = r2 * 5 + c1  # 左下(r2, c1)

        result.append(char2.get(idx_a, '?'))
        result.append(char3.get(idx_b, '?'))

    return ''.join(result)


def decrypt(ciphertext, key1='', key2=''):
    """
    四方密码解密

    参数:
        ciphertext (str): 密文
        key1 (str): 第一个密钥
        key2 (str): 第二个密钥

    返回:
        str: 明文
    """
    square1 = _generate_square('')
    square2 = _generate_square(key1)
    square3 = _generate_square(key2)
    square4 = _generate_square('')

    char1 = _build_char_map(square1)
    char4 = _build_char_map(square4)
    pos2 = _build_pos_map(square2)
    pos3 = _build_pos_map(square3)

    ciphertext = ciphertext.upper().replace(' ', '')
    if len(ciphertext) % 2 == 1:
        ciphertext += 'X'

    result = []
    for i in range(0, len(ciphertext), 2):
        a, b = ciphertext[i], ciphertext[i + 1]
        if a not in pos2 or b not in pos3:
            result.extend([a, b])
            continue

        r1, c2 = pos2[a]  # 在右上方的位置
        r2, c1 = pos3[b]  # 在左下方的位置

        idx_a = r1 * 5 + c1  # 左上(r1, c1)
        idx_b = r2 * 5 + c2  # 右下(r2, c2)

        result.append(char1.get(idx_a, '?'))
        result.append(char4.get(idx_b, '?'))

    return ''.join(result)