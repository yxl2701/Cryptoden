"""
Playfair密码 (普莱费尔密码)
==========================
一种使用5x5矩阵的双字母替换密码

【加密原理】
1. 构造5x5密钥矩阵（I和J共用一格）
2. 将明文分成双字母组
3. 根据三个规则进行替换：
   - 同行：向右移一位
   - 同列：向下移一位
   - 不同行不同列：形成矩形对角交换

【密钥矩阵示例】
密钥: PLAYFAIR
矩阵:
P L A Y F
I/J R B C D
E G H K M
N O Q S T
U V W X Z
"""

def create_matrix(key):
    """创建5x5密钥矩阵"""
    key = key.upper().replace('J', 'I')
    matrix = []
    used = set()
    
    for char in key:
        if char.isalpha() and char not in used:
            matrix.append(char)
            used.add(char)
    
    for char in 'ABCDEFGHIKLMNOPQRSTUVWXYZ':
        if char not in used:
            matrix.append(char)
            used.add(char)
    
    return [matrix[i:i+5] for i in range(0, 25, 5)]

def find_position(matrix, char):
    """查找字符在矩阵中的位置"""
    char = char.upper().replace('J', 'I')
    for i, row in enumerate(matrix):
        for j, c in enumerate(row):
            if c == char:
                return i, j
    return None

def prepare_text(text):
    """准备明文：分组并插入X"""
    text = text.upper().replace('J', 'I')
    text = ''.join(c for c in text if c.isalpha())
    
    result = []
    i = 0
    while i < len(text):
        if i + 1 >= len(text):
            result.append(text[i] + 'X')
            i += 1
        elif text[i] == text[i + 1]:
            result.append(text[i] + 'X')
            i += 1
        else:
            result.append(text[i] + text[i + 1])
            i += 2
    
    return result

def encrypt(plaintext, key='PLAYFAIR'):
    """Playfair加密"""
    if not key:
        return "错误: 请输入密钥"
    
    matrix = create_matrix(key)
    pairs = prepare_text(plaintext)
    result = []
    
    for pair in pairs:
        r1, c1 = find_position(matrix, pair[0])
        r2, c2 = find_position(matrix, pair[1])
        
        if r1 == r2:
            result.append(matrix[r1][(c1 + 1) % 5] + matrix[r2][(c2 + 1) % 5])
        elif c1 == c2:
            result.append(matrix[(r1 + 1) % 5][c1] + matrix[(r2 + 1) % 5][c2])
        else:
            result.append(matrix[r1][c2] + matrix[r2][c1])
    
    return ''.join(result)

def decrypt(ciphertext, key='PLAYFAIR'):
    """Playfair解密"""
    if not key:
        return "错误: 请输入密钥"
    
    ciphertext = ciphertext.upper().replace(' ', '')
    if len(ciphertext) % 2 != 0:
        return "错误: 密文长度必须为偶数"
    
    matrix = create_matrix(key)
    result = []
    
    for i in range(0, len(ciphertext), 2):
        pair = ciphertext[i:i+2]
        r1, c1 = find_position(matrix, pair[0])
        r2, c2 = find_position(matrix, pair[1])
        
        if r1 == r2:
            result.append(matrix[r1][(c1 - 1) % 5] + matrix[r2][(c2 - 1) % 5])
        elif c1 == c2:
            result.append(matrix[(r1 - 1) % 5][c1] + matrix[(r2 - 1) % 5][c2])
        else:
            result.append(matrix[r1][c2] + matrix[r2][c1])
    
    return ''.join(result)
