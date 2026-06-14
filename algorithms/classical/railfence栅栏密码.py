"""
栅栏密码加密模块
================

【算法介绍】
栅栏密码（Rail Fence Cipher）是一种换位密码（Transposition Cipher），
其历史可追溯到古希腊时期。它的名称来源于加密时字符排列的形状像栅栏。

与替换密码不同，换位密码不改变字符本身，只改变字符的位置。

【加密原理】
栅栏密码将明文按"之"字形（W形）排列在多行（栅栏）上，然后逐行读取得到密文。

以2栏为例：
明文：HELLO WORLD
排列：
  H . L . O . O . L .
  . E . L . W . R . D
读取：HLOOLELWRD

以3栏为例：
明文：HELLO WORLD
排列：
  H . . . O . . . R . .
  . E . L . W . O . L .
  . . L . . . O . . . D
读取：HORELWOLL D

【示例】
明文：ATTACK AT DAWN
栅栏数：2
排列：
  A . T . C . A . D . W .
  . T . A . K . T . A . N
读取：ATCADW TAKTAN
密文：ATCADWTAKTAN

【安全性】
栅栏密码安全性较低：
1. 栅栏数有限，容易暴力破解
2. 字符本身不变，只是位置改变
3. 密文长度与明文相同

【参数说明】
- rails: 栅栏数（行数），最小为2
"""

def encrypt(plaintext, rails=2):
    """
    栅栏密码加密函数
    
    将明文按之字形排列在多行上，然后逐行读取得到密文。
    
    参数:
        plaintext (str): 明文
        rails (int): 栅栏数（行数），最小为2
    
    返回:
        str: 密文
    
    加密过程:
        1. 创建rails个空列表，每个代表一行
        2. 遍历明文中的每个字符
        3. 按之字形将字符放入对应的行
           - 从第0行开始向下
           - 到达最后一行后改为向上
           - 到达第0行后改为向下
        4. 逐行读取所有字符，拼接成密文
    
    示例:
        >>> encrypt("HELLO", 2)
        'HLOEL'
        >>> encrypt("HELLO", 3)
        'HOLEL'
    """
    if rails < 2:
        rails = 2
    
    # 创建rails个空列表，每个列表代表一行
    fence = [[] for _ in range(rails)]
    
    # 当前所在的行
    rail = 0
    # 移动方向：1表示向下，-1表示向上
    direction = 1
    
    for char in plaintext:
        # 将当前字符放入对应的行
        fence[rail].append(char)
        
        # 更新行号
        rail += direction
        
        # 到达边界时改变方向
        if rail == 0 or rail == rails - 1:
            direction = -direction
    
    # 逐行读取，拼接成密文
    return ''.join([''.join(row) for row in fence])


def decrypt(ciphertext, rails=2):
    """
    栅栏密码解密函数（指定栅栏数）
    
    根据栅栏数将密文还原为明文。
    
    参数:
        ciphertext (str): 密文
        rails (int): 栅栏数（行数）
    
    返回:
        str: 明文
    
    解密过程:
        1. 创建rails×n的网格，标记之字形路径
        2. 按顺序将密文字符填入标记位置
        3. 按之字形顺序读取，得到明文
    """
    if rails < 2:
        rails = 2
    
    n = len(ciphertext)
    
    # 创建rails行n列的网格
    fence = [[''] * n for _ in range(rails)]
    
    # 第一步：标记之字形路径
    rail = 0
    direction = 1
    for i in range(n):
        fence[rail][i] = '*'  # 标记这个位置有字符
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction = -direction
    
    # 第二步：按行顺序填入密文字符
    index = 0
    for r in range(rails):
        for c in range(n):
            if fence[r][c] == '*' and index < n:
                fence[r][c] = ciphertext[index]
                index += 1
    
    # 第三步：按之字形顺序读取明文
    result = []
    rail = 0
    direction = 1
    for i in range(n):
        result.append(fence[rail][i])
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction = -direction
    
    return ''.join(result)



def decrypt_all(ciphertext):
    """
    爆破所有可能的栅栏数
    
    尝试栅栏数2到10，输出所有解密结果。
    
    参数:
        ciphertext (str): 密文
    
    返回:
        str: 所有可能的解密结果
    """
    results = []
    
    # 尝试栅栏数2到10
    for rails in range(2, 11):
        plaintext = decrypt(ciphertext, rails)
        results.append(f"栅栏数 {rails}: {plaintext}")
    
    return '\n'.join(results)

