"""
社会主义核心价值观编码模块
=========================

【编码原理】
社会主义核心价值观编码是一种将文本映射为24个核心价值观词汇的编码方式。
每个词汇对应一个字母（A-X），常用于CTF隐写题。

编码表（24个唯一词汇）：
富强=A 民主=B 文明=C 和谐=D 自由=E 平等=F 公正=G 法治=H
爱国=I 敬业=J 诚信=K 友善=L 富强次=M 民主次=N 文明次=O 和谐次=P
自由次=Q 平等次=R 公正次=S 法治次=T 爱国次=U 敬业次=V 诚信次=W 友善次=X

【示例】
  输入: HELLO
  输出: 法治 自由 友善 友善 文明次
"""

ALGORITHM_NAME = "社会主义核心价值观编码"
ALGORITHM_DESC = "社会主义核心价值观编码，24词映射编码"

# 24个核心价值观词汇（对应A-X，第二组用"次"标记区分）
VALUES = [
    '富强', '民主', '文明', '和谐',
    '自由', '平等', '公正', '法治',
    '爱国', '敬业', '诚信', '友善',
    '富强次', '民主次', '文明次', '和谐次',
    '自由次', '平等次', '公正次', '法治次',
    '爱国次', '敬业次', '诚信次', '友善次',
]

# 构建映射
CHAR_TO_VALUE = {}
VALUE_TO_CHAR = {}
for i, v in enumerate(VALUES):
    c = chr(ord('A') + i)
    VALUE_TO_CHAR[v] = c
    CHAR_TO_VALUE[c] = v


def encrypt(plaintext):
    plaintext = plaintext.upper().replace(' ', '')
    result = []
    for c in plaintext:
        if c in CHAR_TO_VALUE:
            result.append(CHAR_TO_VALUE[c])
        else:
            result.append(c)
    return ' '.join(result)


def decrypt(ciphertext):
    parts = ciphertext.replace('，', ' ').replace(',', ' ').split()
    if not parts:
        text = ciphertext.replace(' ', '')
        parts = [text[i:i+2] for i in range(0, len(text), 2)]

    result = []
    for p in parts:
        if p in VALUE_TO_CHAR:
            result.append(VALUE_TO_CHAR[p])
        else:
            result.append('?')

    return ''.join(result)