"""
Base64编码加密模块
==================

【算法介绍】
Base64是一种基于64个可打印字符来表示二进制数据的编码方法。
它由MIME（多用途互联网邮件扩展）规范定义，广泛用于电子邮件、
网页传输等场景，用于传输二进制数据。

【编码原理】
Base64将每3个字节（24位）的数据编码为4个字符：
1. 将3个字节的数据分成4组，每组6位
2. 每组6位可以表示0-63的值
3. 根据Base64字符表转换为对应字符

Base64字符表（64个字符）：
  A-Z: 0-25
  a-z: 26-51
  0-9: 52-61
  +: 62
  /: 63

【填充】
当输入数据不是3的倍数时：
- 剩余1个字节：补2个等号（=）
- 剩余2个字节：补1个等号（=）

【示例】
明文：Hello
二进制：01001000 01100101 01101100 01101100 01101111
分组：010010 000110 010101 101100 011011 000110 1111?? ??
编码：S G V s b G 8 =
Base64：SGVsbG8=

【特点】
1. 编码后数据量增加约33%
2. 可安全传输，只使用可打印ASCII字符
3. 不是加密，只是编码，可轻松解码
"""

ALGORITHM_NAME = "Base64"
ALGORITHM_DESC = "Base64编码，将二进制数据转换为可打印字符"

PARAMS = []

import base64


def _clean_base64(text):
    cleaned = ''.join(text.split())
    if not cleaned:
        return ''
    padding = (-len(cleaned)) % 4
    return cleaned + ('=' * padding)


def encrypt(plaintext):
    """
    Base64编码函数
    
    将字符串编码为Base64格式。
    
    参数:
        plaintext (str): 明文
    
    返回:
        str: Base64编码结果
    
    编码过程:
        1. 将字符串转换为UTF-8字节
        2. 使用base64模块进行编码
        3. 将字节结果解码为字符串
    
    示例:
        >>> encrypt("Hello")
        'SGVsbG8='
        >>> encrypt("Hello World")
        'SGVsbG8gV29ybGQ='
    """
    try:
        # 将字符串编码为字节，然后进行Base64编码
        encoded_bytes = base64.b64encode(plaintext.encode('utf-8'))
        # 将字节解码为字符串返回
        return encoded_bytes.decode('utf-8')
    except Exception as e:
        return f"编码错误: {str(e)}"


def decrypt(ciphertext):
    """
    Base64解码函数
    
    将Base64字符串解码为原始字符串。
    
    参数:
        ciphertext (str): Base64编码的字符串
    
    返回:
        str: 解码后的原始字符串
    
    示例:
        >>> decrypt("SGVsbG8=")
        'Hello'
    """
    try:
        # 将Base64字符串解码为字节，然后解码为UTF-8字符串
        cleaned = _clean_base64(ciphertext)
        decoded_bytes = base64.b64decode(cleaned, validate=True)
        return decoded_bytes.decode('utf-8')
    except Exception as e:
        return f"解码错误: {str(e)}"

