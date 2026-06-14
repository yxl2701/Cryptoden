"""
路线密码加密模块
===============

【算法介绍】
路线密码（Route Cipher）是一种换位密码，将明文按行写入矩阵，
然后按特定路线（如螺旋、对角线等）读取。

【加密原理】
1. 将明文按行写入矩阵
2. 按指定路线读取矩阵中的字符
3. 支持的路线：螺旋向内、螺旋向外、蛇形、对角线

【示例】
明文: ATTACKATDAWN
路线: 螺旋向内
密文: ...

【参数说明】
- route: 路线类型
  - 'spiral_in': 从左上角顺时针螺旋向内
  - 'spiral_out': 从中心逆时针螺旋向外
  - 'snake': 蛇形（第一行从左到右，第二行从右到左）
  - 'diagonal': 对角线读取
- cols: 矩阵列数（默认自动计算）
"""

ALGORITHM_NAME = "路线密码"
ALGORITHM_DESC = "Route Cipher，按指定路线读取矩阵的换位密码"


def encrypt(plaintext, route='spiral_in', cols=0):
    """
    路线密码加密

    参数:
        plaintext (str): 明文
        route (str): 路线类型
        cols (int): 矩阵列数

    返回:
        str: 密文
    """
    plaintext = plaintext.replace(' ', '')
    n = len(plaintext)

    if cols <= 0:
        cols = max(3, int(n ** 0.5))

    rows = (n + cols - 1) // cols

    # 填充矩阵
    matrix = [[''] * cols for _ in range(rows)]
    for i, c in enumerate(plaintext):
        r = i // cols
        c_idx = i % cols
        matrix[r][c_idx] = c

    result = []

    if route == 'spiral_in':
        result = _spiral_in(matrix, rows, cols)
    elif route == 'spiral_out':
        result = _spiral_out(matrix, rows, cols)
    elif route == 'snake':
        result = _snake(matrix, rows, cols)
    elif route == 'diagonal':
        result = _diagonal(matrix, rows, cols)
    else:
        result = _spiral_in(matrix, rows, cols)

    return ''.join(c for c in result if c)


def decrypt(ciphertext, route='spiral_in', cols=0):
    """
    路线密码解密

    参数:
        ciphertext (str): 密文
        route (str): 路线类型
        cols (int): 矩阵列数

    返回:
        str: 明文
    """
    n = len(ciphertext)

    if cols <= 0:
        cols = max(3, int(n ** 0.5))

    rows = (n + cols - 1) // cols
    total = rows * cols
    empty = total - n

    # 先按路线获取读取顺序
    matrix = [[''] * cols for _ in range(rows)]
    # 用占位符填充
    for r in range(rows):
        for c in range(cols):
            matrix[r][c] = '*'

    if route == 'spiral_in':
        order = _get_spiral_in_order(rows, cols)
    elif route == 'spiral_out':
        order = _get_spiral_out_order(rows, cols)
    elif route == 'snake':
        order = _get_snake_order(rows, cols)
    elif route == 'diagonal':
        order = _get_diagonal_order(rows, cols)
    else:
        order = _get_spiral_in_order(rows, cols)

    # 过滤掉空位置
    valid_order = []
    for r, c in order:
        if r < rows and c < cols:
            idx = r * cols + c
            if idx < n:
                valid_order.append((r, c))

    # 按顺序填充密文
    idx = 0
    for r, c in valid_order:
        if idx < len(ciphertext):
            matrix[r][c] = ciphertext[idx]
            idx += 1

    # 按行读取
    result = []
    for r in range(rows):
        for c in range(cols):
            if matrix[r][c] != '*' and matrix[r][c] != '':
                result.append(matrix[r][c])

    return ''.join(result)


def _spiral_in(matrix, rows, cols):
    """顺时针螺旋向内"""
    result = []
    top, bottom, left, right = 0, rows - 1, 0, cols - 1

    while top <= bottom and left <= right:
        # 向右
        for c in range(left, right + 1):
            result.append(matrix[top][c])
        top += 1
        # 向下
        for r in range(top, bottom + 1):
            result.append(matrix[r][right])
        right -= 1
        # 向左
        if top <= bottom:
            for c in range(right, left - 1, -1):
                result.append(matrix[bottom][c])
            bottom -= 1
        # 向上
        if left <= right:
            for r in range(bottom, top - 1, -1):
                result.append(matrix[r][left])
            left += 1

    return result


def _spiral_out(matrix, rows, cols):
    """逆时针螺旋向外"""
    # 先获取螺旋向内顺序，然后反转
    inner = _spiral_in(matrix, rows, cols)
    return list(reversed(inner))


def _snake(matrix, rows, cols):
    """蛇形读取"""
    result = []
    for r in range(rows):
        if r % 2 == 0:
            for c in range(cols):
                result.append(matrix[r][c])
        else:
            for c in range(cols - 1, -1, -1):
                result.append(matrix[r][c])
    return result


def _diagonal(matrix, rows, cols):
    """对角线读取"""
    result = []
    for diag in range(rows + cols - 1):
        r = 0 if diag < cols else diag - cols + 1
        c = diag if diag < cols else cols - 1
        while r < rows and c >= 0:
            result.append(matrix[r][c])
            r += 1
            c -= 1
    return result


def _get_spiral_in_order(rows, cols):
    """获取螺旋向内顺序"""
    order = []
    top, bottom, left, right = 0, rows - 1, 0, cols - 1

    while top <= bottom and left <= right:
        for c in range(left, right + 1):
            order.append((top, c))
        top += 1
        for r in range(top, bottom + 1):
            order.append((r, right))
        right -= 1
        if top <= bottom:
            for c in range(right, left - 1, -1):
                order.append((bottom, c))
            bottom -= 1
        if left <= right:
            for r in range(bottom, top - 1, -1):
                order.append((r, left))
            left += 1

    return order


def _get_spiral_out_order(rows, cols):
    """获取螺旋向外顺序"""
    order = _get_spiral_in_order(rows, cols)
    return list(reversed(order))


def _get_snake_order(rows, cols):
    """获取蛇形顺序"""
    order = []
    for r in range(rows):
        if r % 2 == 0:
            for c in range(cols):
                order.append((r, c))
        else:
            for c in range(cols - 1, -1, -1):
                order.append((r, c))
    return order


def _get_diagonal_order(rows, cols):
    """获取对角线顺序"""
    order = []
    for diag in range(rows + cols - 1):
        r = 0 if diag < cols else diag - cols + 1
        c = diag if diag < cols else cols - 1
        while r < rows and c >= 0:
            order.append((r, c))
            r += 1
            c -= 1
    return order