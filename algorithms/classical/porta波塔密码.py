"""
Porta密码 (波塔密码)
===================
一种多表替换密码，使用双字母分组

【加密原理】
使用13个2x2矩阵，每个矩阵对应字母表的一半
根据密钥字母选择矩阵进行替换

【密钥表】
A/B: (A B C D E F G H I J K L M) <-> (N O P Q R S T U V W X Y Z)
C/D: (A B C D E F G H I J K L M) <-> (O P Q R S T U V W X Y Z N)
...
"""

PORTA_TABLE = {
    'A': 'NOPQRSTUVWXYZABCDEFGHIJKLM',
    'B': 'NOPQRSTUVWXYZABCDEFGHIJKLM',
    'C': 'OPQRSTUVWXYZNABCDEFGHIJKLM',
    'D': 'OPQRSTUVWXYZNABCDEFGHIJKLM',
    'E': 'PQRSTUVWXYZNOABCDEFGHIJKLM',
    'F': 'PQRSTUVWXYZNOABCDEFGHIJKLM',
    'G': 'QRSTUVWXYZNOPABCDEFGHIJKLM',
    'H': 'QRSTUVWXYZNOPABCDEFGHIJKLM',
    'I': 'RSTUVWXYZNOPQABCDEFGHIJKLM',
    'J': 'RSTUVWXYZNOPQABCDEFGHIJKLM',
    'K': 'STUVWXYZNOPQRABCDEFGHIJKLM',
    'L': 'STUVWXYZNOPQRABCDEFGHIJKLM',
    'M': 'TUVWXYZNOPQRSABCDEFGHIJKLM',
    'N': 'TUVWXYZNOPQRSABCDEFGHIJKLM',
    'O': 'UVWXYZNOPQRSTABCDEFGHIJKLM',
    'P': 'UVWXYZNOPQRSTABCDEFGHIJKLM',
    'Q': 'VWXYZNOPQRSTUABCDEFGHIJKLM',
    'R': 'VWXYZNOPQRSTUABCDEFGHIJKLM',
    'S': 'WXYZNOPQRSTUVABCDEFGHIJKLM',
    'T': 'WXYZNOPQRSTUVABCDEFGHIJKLM',
    'U': 'XYZNOPQRSTUVWABCDEFGHIJKLM',
    'V': 'XYZNOPQRSTUVWABCDEFGHIJKLM',
    'W': 'YZNOPQRSTUVWXABCDEFGHIJKLM',
    'X': 'YZNOPQRSTUVWXABCDEFGHIJKLM',
    'Y': 'ZNOPQRSTUVWXYABCDEFGHIJKLM',
    'Z': 'ZNOPQRSTUVWXYABCDEFGHIJKLM',
}

def encrypt(plaintext, key='KEY'):
    """Porta加密"""
    if not key:
        return "错误: 请输入密钥"
    
    plaintext = ''.join(c.upper() for c in plaintext if c.isalpha())
    key = ''.join(c.upper() for c in key if c.isalpha())
    
    result = []
    for i, p in enumerate(plaintext):
        k = key[i % len(key)]
        if p < 'N':
            idx = ord(p) - ord('A')
            result.append(PORTA_TABLE[k][idx])
        else:
            idx = ord(p) - ord('N')
            result.append(PORTA_TABLE[k][idx + 13])
    
    return ''.join(result)

def decrypt(ciphertext, key='KEY'):
    """Porta解密"""
    if not key:
        return "错误: 请输入密钥"
    
    ciphertext = ''.join(c.upper() for c in ciphertext if c.isalpha())
    key = ''.join(c.upper() for c in key if c.isalpha())
    
    result = []
    for i, c in enumerate(ciphertext):
        k = key[i % len(key)]
        table = PORTA_TABLE[k]
        idx = table.index(c)
        
        if idx < 13:
            result.append(chr(ord('A') + idx))
        else:
            result.append(chr(ord('N') + idx - 13))
    
    return ''.join(result)
