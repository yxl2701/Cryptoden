"""
URL编码加密模块
===============

【算法介绍】
URL编码（也称为百分号编码，Percent-encoding）是一种将字符转换为
可在URL中安全传输的格式的编码方法。

URL中只能包含ASCII字符集中的可打印字符，其他字符需要进行编码。

【编码原理】
URL编码将非安全字符转换为%XX格式：
- XX是字符的十六进制ASCII码值
- 例如：空格编码为%20，中文"你好"编码为%E4%BD%A0%E5%A5%BD

【需要编码的字符】
1. 保留字符：! * ' ( ) ; : @ & = + $ , / ? % # [ ]
2. 非ASCII字符：中文、日文等
3. 控制字符：空格、换行等

【示例】
明文：Hello World
编码：Hello%20World

明文：你好
编码：%E4%BD%A0%E5%A5%BD

【应用场景】
1. URL参数传递
2. 表单数据提交
3. HTTP请求编码
"""

import urllib.parse

def encrypt(plaintext):
    """
    URL编码函数
    
    将字符串编码为URL安全格式。
    
    参数:
        plaintext (str): 明文
    
    返回:
        str: URL编码结果
    
    编码过程:
        1. 使用urllib.parse.quote进行编码
        2. safe参数指定哪些字符不需要编码
        3. 空字符串表示所有非安全字符都编码
    
    示例:
        >>> encrypt("Hello World")
        'Hello%20World'
        >>> encrypt("你好")
        '%E4%BD%A0%E5%A5%BD'
    """
    return urllib.parse.quote(plaintext, safe='')


def decrypt(ciphertext):
    """
    URL解码函数
    
    将URL编码的字符串还原为原始字符串。
    
    参数:
        ciphertext (str): URL编码的字符串
    
    返回:
        str: 解码后的原始字符串
    
    示例:
        >>> decrypt("Hello%20World")
        'Hello World'
        >>> decrypt("%E4%BD%A0%E5%A5%BD")
        '你好'
    """
    try:
        return urllib.parse.unquote(ciphertext)
    except Exception as e:
        return f"解码错误: {str(e)}"

