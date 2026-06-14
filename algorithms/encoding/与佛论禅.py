"""
与佛论禅编码模块
===============

【编码原理】
与佛论禅是一种中文CTF中常见的编码方式，将文本中的字符
映射为佛教相关词汇。

编码表：
佛=A 陀=B 般=C 若=D 波=E 罗=F 蜜=G 多=H
心=I 经=J 如=K 是=L 照=M 见=N 五=O 蕴=P
皆=Q 空=R 度=S 一=T 切=U 苦=V 厄=W 矣=X

【示例】
  输入: HELLO
  输出: 陀般罗罗波
"""

ALGORITHM_NAME = "与佛论禅"
ALGORITHM_DESC = "与佛论禅编码，佛教词汇映射编码"

# 编码表（对应A-X）
BUDDHIST_WORDS = [
    '佛', '陀', '般', '若', '波', '罗', '蜜', '多',
    '心', '经', '如', '是', '照', '见', '五', '蕴',
    '皆', '空', '度', '一', '切', '苦', '厄', '矣',
]

CHAR_TO_WORD = {}
WORD_TO_CHAR = {}
for i, w in enumerate(BUDDHIST_WORDS):
    c = chr(ord('A') + i)
    CHAR_TO_WORD[c] = w
    WORD_TO_CHAR[w] = c


def encrypt(plaintext):
    """
    与佛论禅编码

    参数:
        plaintext (str): 明文

    返回:
        str: 编码结果
    """
    plaintext = plaintext.upper().replace(' ', '')
    result = []
    for c in plaintext:
        if c in CHAR_TO_WORD:
            result.append(CHAR_TO_WORD[c])
        else:
            result.append(c)
    return ' '.join(result)


def decrypt(ciphertext):
    """
    与佛论禅解码

    参数:
        ciphertext (str): 编码文本

    返回:
        str: 解码结果
    """
    parts = ciphertext.replace('，', ' ').replace(',', ' ').split()
    if not parts:
        text = ciphertext.replace(' ', '')
        parts = [text[i] for i in range(len(text))]

    result = []
    for p in parts:
        if p in WORD_TO_CHAR:
            result.append(WORD_TO_CHAR[p])
        else:
            result.append('?')

    return ''.join(result)