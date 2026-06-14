"""
培根密码加密模块
================

【算法介绍】
培根密码（Bacon's Cipher）是由英国哲学家弗朗西斯·培根（Francis Bacon）
在1605年发明的一种隐写术（Steganography）。

与其他密码不同，培根密码的目的是将秘密信息隐藏在普通文本中，
使外人看不出任何异常。

【加密原理】
培根密码将每个字母编码为5位二进制序列，使用A和B表示：
- 标准版（24字母）：I和J共用一个编码，U和V共用一个编码
- 变体版（26字母）：每个字母独立编码

编码表（标准版）：
A=AAAAA  B=AAAAB  C=AAABA  D=AAABB  E=AABAA
F=AABAB  G=AABBA  H=AABBB  I/J=ABAAA  K=ABABA
L=ABABB  M=ABBAA  N=ABBAB  O=ABBBA  P=ABBBB
Q=BAAAA  R=BAAAB  S=BAABA  T=BAABB  U/V=BABAA
W=BABBA  X=BABBB  Y=BBAAA  Z=BBAAB

【隐写应用】
培根密码的真正用途是隐写：
1. 准备两套字体（或两种样式）
2. 字体A对应编码中的A，字体B对应编码中的B
3. 用普通文本作为载体，通过切换字体隐藏信息

例如，明文"HELLO"编码为：
AABBB AABAA ABABB ABABB ABBBA

载体文本可以是任意足够长的文本，通过字体变化隐藏这些A/B序列。

【示例】
明文：HELLO
编码：AABBB AABAA ABABB ABABB ABBBA
输出：AABBBAABAAABABBABABBABBBA

【安全性】
培根密码作为隐写术时安全性较高，因为载体文本看起来很正常。
但直接使用编码形式时很容易被识别和解码。

【参数说明】
- variant: 版本选择，'standard'为24字母版，'variant'为26字母版
"""

# 标准版编码表（24字母，I/J和U/V共用）
BACON_STANDARD = {
    'A': 'AAAAA', 'B': 'AAAAB', 'C': 'AAABA', 'D': 'AAABB', 'E': 'AABAA',
    'F': 'AABAB', 'G': 'AABBA', 'H': 'AABBB', 'I': 'ABAAA', 'J': 'ABAAB',
    'K': 'ABABA', 'L': 'ABABB', 'M': 'ABBAA', 'N': 'ABBAB', 'O': 'ABBBA',
    'P': 'ABBBB', 'Q': 'BAAAA', 'R': 'BAAAB', 'S': 'BAABA', 'T': 'BAABB',
    'U': 'BABAA', 'V': 'BABAB', 'W': 'BABBA', 'X': 'BABBB', 'Y': 'BBAAA', 'Z': 'BBAAB'
}

# 变体版编码表（26字母，每个字母独立）
BACON_VARIANT = {
    'A': 'AAAAA', 'B': 'AAAAB', 'C': 'AAABA', 'D': 'AAABB', 'E': 'AABAA',
    'F': 'AABAB', 'G': 'AABBA', 'H': 'AABBB', 'I': 'ABAAA', 'J': 'ABAAB',
    'K': 'ABABA', 'L': 'ABABB', 'M': 'ABBAA', 'N': 'ABBAB', 'O': 'ABBBA',
    'P': 'ABBBB', 'Q': 'BAAAA', 'R': 'BAAAB', 'S': 'BAABA', 'T': 'BAABB',
    'U': 'BABAA', 'V': 'BABAB', 'W': 'BABBA', 'X': 'BABBB', 'Y': 'BBAAA', 'Z': 'BBBAB'
}

def encrypt(plaintext, variant='standard'):
    """
    培根密码加密函数
    
    将明文中的每个字母编码为5位A/B序列。
    
    参数:
        plaintext (str): 明文
        variant (str): 版本，'standard'或'variant'
    
    返回:
        str: 编码结果，字母间用空格分隔
    
    加密过程:
        1. 选择编码表（标准版或变体版）
        2. 遍历明文中的每个字符
        3. 将字母转换为大写后查找编码
        4. 非字母字符保持不变
        5. 用空格分隔各字母的编码
    
    示例:
        >>> encrypt("HELLO", "standard")
        'AABBB AABAA ABABB ABABB ABBBA'
        >>> encrypt("HELLO", "variant")
        'AABBB AABAA ABABB ABABB ABBBA'
    """
    # 根据版本选择编码表
    table = BACON_VARIANT if variant == 'variant' else BACON_STANDARD
    
    result = []
    
    for char in plaintext.upper():
        if char in table:
            # 查找字母对应的5位编码
            result.append(table[char])
        else:
            # 非字母字符保持不变
            result.append(char)
    
    # 用空格分隔各编码，便于阅读
    return ' '.join(result)


def decrypt(ciphertext, variant='standard'):
    """
    培根密码解密函数
    
    将A/B序列解码为字母。
    
    参数:
        ciphertext (str): 密文（A/B序列）
        variant (str): 版本
    
    返回:
        str: 明文
    
    解密过程:
        1. 移除空格和换行
        2. 每5个字符一组
        3. 查表转换为字母
        4. 无法识别的编码用?表示
    """
    # 根据版本选择解码表
    table = BACON_VARIANT if variant == 'variant' else BACON_STANDARD
    
    # 移除空格和换行，统一转为大写
    ciphertext = ciphertext.replace(' ', '').replace('\n', '').upper()
    
    result = []
    
    # 每5个字符为一组进行解码
    for i in range(0, len(ciphertext), 5):
        chunk = ciphertext[i:i+5]
        
        if chunk in table:
            result.append(table[chunk])
        else:
            # 无法识别的编码用?表示
            result.append('?')
    
    return ''.join(result)

