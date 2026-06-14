"""
Polybius密码 (波利比乌斯方阵)
=============================
使用5x5方阵将字母转换为坐标对

【加密原理】
   1 2 3 4 5
1 A B C D E
2 F G H I/J K
3 L M N O P
4 Q R S T U
5 V W X Y Z

每个字母用行号和列号表示，如 A=11, B=12, H=23

【变体】
可以使用自定义密钥重排方阵
"""

DEFAULT_SQUARE = [
    ['A', 'B', 'C', 'D', 'E'],
    ['F', 'G', 'H', 'I', 'K'],
    ['L', 'M', 'N', 'O', 'P'],
    ['Q', 'R', 'S', 'T', 'U'],
    ['V', 'W', 'X', 'Y', 'Z']
]

def create_square(key=''):
    """创建Polybius方阵"""
    if not key:
        return DEFAULT_SQUARE
    
    key = key.upper().replace('J', 'I')
    chars = []
    used = set()
    
    for c in key:
        if c.isalpha() and c not in used and c != 'J':
            chars.append(c)
            used.add(c)
    
    for c in 'ABCDEFGHIKLMNOPQRSTUVWXYZ':
        if c not in used:
            chars.append(c)
            used.add(c)
    
    return [chars[i:i+5] for i in range(0, 25, 5)]

def encrypt(plaintext, key=''):
    """Polybius加密"""
    square = create_square(key)
    result = []
    
    for char in plaintext.upper():
        if char == 'J':
            char = 'I'
        if char.isalpha():
            for i, row in enumerate(square):
                for j, c in enumerate(row):
                    if c == char:
                        result.append(f"{i+1}{j+1}")
                        break
    
    return ' '.join(result)

def decrypt(ciphertext, key=''):
    """Polybius解密"""
    square = create_square(key)
    ciphertext = ciphertext.replace(' ', '').replace(',', ' ')
    
    result = []
    nums = [c for c in ciphertext if c.isdigit()]
    
    for i in range(0, len(nums), 2):
        if i + 1 < len(nums):
            row = int(nums[i]) - 1
            col = int(nums[i+1]) - 1
            if 0 <= row < 5 and 0 <= col < 5:
                result.append(square[row][col])
    
    return ''.join(result)
