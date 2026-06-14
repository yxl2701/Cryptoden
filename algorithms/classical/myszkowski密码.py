"""
Myszkowski密码加密模块
=====================

【算法介绍】
Myszkowski密码是列换位密码（Columnar Transposition）的一种变体，
由Émile Victor Théodore Myszkowski提出。与标准列换位不同，
Myszkowski允许密钥中出现重复字母，相同字母对应的列按行读取。

【加密原理】
1. 将明文按行写入矩阵，列数为密钥长度
2. 密钥中相同字母对应的列，按行顺序一起读取
3. 不同字母组按字母顺序读取

【示例】
密钥: TOMATO (T重复)
明文: ATTACKATDAWN
密文: ...

【参数说明】
- key: 密钥（可包含重复字母）
"""

ALGORITHM_NAME = "Myszkowski密码"
ALGORITHM_DESC = "Myszkowski列换位密码，支持重复密钥的列换位变体"


def encrypt(plaintext, key=''):
    """
    Myszkowski密码加密

    参数:
        plaintext (str): 明文
        key (str): 密钥

    返回:
        str: 密文
    """
    if not key:
        key = 'KEY'

    key = key.upper()
    num_cols = len(key)
    plaintext = plaintext.replace(' ', '')

    # 计算行数
    num_rows = (len(plaintext) + num_cols - 1) // num_cols

    # 填充矩阵
    matrix = []
    for r in range(num_rows):
        row = []
        for c in range(num_cols):
            idx = r * num_cols + c
            if idx < len(plaintext):
                row.append(plaintext[idx])
            else:
                row.append('')
        matrix.append(row)

    # 按相同字母分组
    # 获取排序后的列顺序，但相同字母的列按行优先读取
    # 先按字母排序，相同字母按原始顺序
    col_info = [(key[i], i) for i in range(num_cols)]

    # 分组：相同字母的列归为一组
    from collections import defaultdict
    groups = defaultdict(list)
    for ch, col_idx in col_info:
        groups[ch].append(col_idx)

    # 按字母顺序处理各组
    sorted_groups = [groups[ch] for ch in sorted(groups.keys())]

    result = []
    for group in sorted_groups:
        # 相同字母的列，按行读取所有列
        for r in range(num_rows):
            for c in group:
                if r < len(matrix) and c < len(matrix[r]) and matrix[r][c] != '':
                    result.append(matrix[r][c])

    return ''.join(result)


def decrypt(ciphertext, key=''):
    """
    Myszkowski密码解密

    参数:
        ciphertext (str): 密文
        key (str): 密钥

    返回:
        str: 明文
    """
    if not key:
        key = 'KEY'

    key = key.upper()
    num_cols = len(key)
    num_rows = (len(ciphertext) + num_cols - 1) // num_cols

    total_cells = num_rows * num_cols
    empty_cells = total_cells - len(ciphertext)

    # 计算每列的字符数（Myszkowski方式）
    from collections import defaultdict
    groups = defaultdict(list)
    for i, ch in enumerate(key):
        groups[ch].append(i)

    sorted_groups = [groups[ch] for ch in sorted(groups.keys())]

    # 分配每列应包含的字符数
    col_lengths = [0] * num_cols

    # 计算完整行数
    full_rows = num_rows
    if empty_cells > 0:
        full_rows = num_rows - 1

    # 基本分配：每列都有full_rows个字符
    for c in range(num_cols):
        col_lengths[c] = full_rows

    # 多余字符分配到各组，按行优先原则
    extra = empty_cells  # 实际是缺少的字符数
    # 对于相同字母组，多余字符在最后一行
    remaining = num_cols - empty_cells  # 最后一行非空列数

    # 重新计算：每列的字符数 = 完整行数 + (该列在最后一行是否有字符)
    # 按列的自然顺序分配最后一行
    for c in range(num_cols):
        col_lengths[c] = num_rows

    # 最后一行中，末尾列可能为空
    # 从最后一列开始减少
    for i in range(empty_cells):
        col_lengths[num_cols - 1 - i] -= 1

    # 按Myszkowski顺序填充
    # 构建加密时的读取顺序
    read_order = []
    for group in sorted_groups:
        for r in range(num_rows):
            for c in group:
                read_order.append((r, c))

    # 过滤掉超出范围的
    read_order = [(r, c) for r, c in read_order
                  if r < num_rows and c < num_cols and
                  not (r == num_rows - 1 and c >= num_cols - empty_cells)]

    # 按读取顺序填充密文
    idx = 0
    filled = {}
    for r, c in read_order:
        if idx < len(ciphertext):
            filled[(r, c)] = ciphertext[idx]
            idx += 1

    # 按行读取结果
    result = []
    for r in range(num_rows):
        for c in range(num_cols):
            if (r, c) in filled:
                result.append(filled[(r, c)])

    return ''.join(result).rstrip('\x00')