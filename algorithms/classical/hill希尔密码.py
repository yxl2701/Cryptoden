"""
Hill密码 (希尔密码)
==================
利用矩阵运算的多字母替换密码

【加密原理】
1. 将字母转换为数字 (A=0, B=1, ..., Z=25)
2. 将明文分成n维向量
3. 用n×n密钥矩阵左乘向量
4. 结果模26得到密文

【示例】
密钥矩阵: [[3,2],[5,1]]
明文: HI -> [7,8]
密文: [3*7+2*8, 5*7+1*8] mod 26 = [37,43] mod 26 = [11,17] -> LR
"""

import numpy as np

def mod_inverse(a, m):
    """求模逆"""
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def matrix_mod_inverse(matrix, mod):
    """求矩阵模逆"""
    det = int(round(np.linalg.det(matrix)))
    det = det % mod
    det_inv = mod_inverse(det, mod)
    
    if det_inv is None:
        return None
    
    adj = np.round(np.linalg.inv(matrix) * np.linalg.det(matrix)).astype(int)
    return (det_inv * adj) % mod

def parse_key_matrix(key, size=2):
    """解析密钥矩阵"""
    try:
        key = key.replace('[', '').replace(']', '').replace('(', '').replace(')', '')
        nums = [int(x.strip()) for x in key.split(',')]
        
        if len(nums) != size * size:
            return None
        
        return np.array(nums).reshape(size, size)
    except:
        return None

def text_to_numbers(text):
    """文本转数字"""
    return [ord(c.upper()) - ord('A') for c in text if c.isalpha()]

def numbers_to_text(nums):
    """数字转文本"""
    return ''.join(chr(int(n % 26) + ord('A')) for n in nums)

def encrypt(plaintext, key='3,2,5,1', size='2'):
    """Hill加密"""
    try:
        size = int(size)
    except:
        size = 2
    
    matrix = parse_key_matrix(key, size)
    if matrix is None:
        return "错误: 密钥格式错误，请输入逗号分隔的数字\n例如: 3,2,5,1 (2x2矩阵)"
    
    plaintext = ''.join(c for c in plaintext.upper() if c.isalpha())
    
    while len(plaintext) % size != 0:
        plaintext += 'X'
    
    result = []
    for i in range(0, len(plaintext), size):
        block = text_to_numbers(plaintext[i:i+size])
        encrypted = np.dot(matrix, block) % 26
        result.extend(encrypted)
    
    return numbers_to_text(result)

def decrypt(ciphertext, key='3,2,5,1', size='2'):
    """Hill解密"""
    try:
        size = int(size)
    except:
        size = 2
    
    matrix = parse_key_matrix(key, size)
    if matrix is None:
        return "错误: 密钥格式错误"
    
    ciphertext = ''.join(c for c in ciphertext.upper() if c.isalpha())
    
    if len(ciphertext) % size != 0:
        return "错误: 密文长度必须是矩阵维度的倍数"
    
    inv_matrix = matrix_mod_inverse(matrix, 26)
    if inv_matrix is None:
        return "错误: 密钥矩阵不可逆，请更换密钥"
    
    result = []
    for i in range(0, len(ciphertext), size):
        block = text_to_numbers(ciphertext[i:i+size])
        decrypted = np.dot(inv_matrix, block) % 26
        result.extend(decrypted)
    
    return numbers_to_text(result)
