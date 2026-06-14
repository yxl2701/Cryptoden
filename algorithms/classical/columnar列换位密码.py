"""
列换位密码加密模块
==================

【算法介绍】
列换位密码（Columnar Transposition Cipher）是一种换位密码，
通过将明文按行写入矩阵，然后按列读取来产生密文。
列的读取顺序由密钥决定。

【加密原理】
1. 将明文按行写入一个矩阵，矩阵的列数由密钥长度决定
2. 根据密钥中字母的字母表顺序，确定各列的读取顺序
3. 按确定的顺序逐列读取字符，得到密文

【示例】
密钥: GERMAN
明文: ATTACK AT DAWN

矩阵（6列）:
  G E R M A N
  -----------
  A T T A C K
  A T D A W N

密钥字母顺序: A(1) E(2) G(3) M(4) N(5) R(6)
按列读取: A(第5列) T(第2列) A(第1列) T(第4列) A(第6列) T(第3列)
         C W K N A D
密文: ATA TCW KNA D

【应用场景】
1. CTF密码题
2. 经典密码学教学
3. 与其他密码组合使用

【参数说明】
- key: 密钥字符串，用于确定列读取顺序，默认为"GERMAN"
"""


def _get_column_order(key: str) -> list:
    """
    根据密钥确定列读取顺序

    返回列索引列表，按密钥字母的字母表顺序排序。
    相同字母按出现顺序处理。

    参数:
        key: 密钥字符串

    返回:
        list: 列索引列表
    """
    # 为每个字符创建 (字符, 原始索引) 对
    indexed = [(char, idx) for idx, char in enumerate(key)]
    # 按字符排序，相同字符按原始索引排序
    indexed.sort(key=lambda x: (x[0], x[1]))
    # 返回排序后的原始索引
    return [idx for _, idx in indexed]


def encrypt(plaintext, key="GERMAN"):
    """
    列换位密码加密

    将明文按行写入矩阵，然后按密钥确定的顺序逐列读取。

    参数:
        plaintext (str): 明文
        key (str): 密钥，用于确定列读取顺序

    返回:
        str: 密文

    示例:
        >>> encrypt("ATTACKATDAWN", "GERMAN")
        'ATATCWKNAD'
    """
    text = plaintext.replace(' ', '')
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


def decrypt(ciphertext, key="GERMAN"):
    """
    列换位密码解密

    根据密钥和密文长度重建矩阵，然后按行读取。

    参数:
        ciphertext (str): 密文
        key (str): 密钥，用于确定列读取顺序

    返回:
        str: 明文

    示例:
        >>> decrypt("ATATCWKNAD", "GERMAN")
        'ATTACKATDAWN'
    """
    num_cols = len(key)
    num_rows = (len(ciphertext) + num_cols - 1) // num_cols

    # 计算每列的字符数
    col_order = _get_column_order(key)
    col_lengths = [num_rows] * num_cols
    total_cells = num_rows * num_cols
    empty_cells = total_cells - len(ciphertext)
    # 最后一行不满，末尾列少一个字符（按自然列顺序）
    for i in range(empty_cells):
        col_lengths[num_cols - 1 - i] -= 1

    # 按列顺序填充密文到矩阵
    matrix = [[''] * num_cols for _ in range(num_rows)]
    idx = 0
    for col in col_order:
        for row in range(col_lengths[col]):
            if idx < len(ciphertext):
                matrix[row][col] = ciphertext[idx]
                idx += 1

    # 按行读取
    result = []
    for row in range(num_rows):
        for col in range(num_cols):
            if matrix[row][col] != '':
                result.append(matrix[row][col])

    return ''.join(result)