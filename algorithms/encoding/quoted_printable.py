"""
Quoted-Printable编码模块
========================

【编码原理】
Quoted-Printable（可打印引用编码）是一种将非ASCII字符和特殊字符
编码为可打印ASCII字符的编码方式，常用于电子邮件传输。

编码规则：
1. 可打印ASCII字符（33-126，除=外）保持不变
2. 等号 = 编码为 =3D
3. 非ASCII字符（>126或<33，含空格?）编码为 =XX（XX为十六进制值）
4. 行末尾的软换行用 = 表示（=后面跟换行符）

【特点】
1. 对人类可读性好（大部分ASCII字符保留原样）
2. 适用于主要包含ASCII文本的数据
3. MIME协议中常用

【应用场景】
1. 电子邮件MIME编码
2. 数据传输中的ASCII保障
3. CTF编码题

【示例】
  输入: Hello Wörld!
  QP: Hello W=C3=B6rld!
"""

ALGORITHM_NAME = "Quoted-Printable"
ALGORITHM_DESC = "Quoted-Printable编码，将非ASCII字符编码为可打印字符"

import quopri


def encrypt(plaintext):
    """
    Quoted-Printable编码

    将字符串编码为Quoted-Printable格式。

    参数:
        plaintext (str): 明文

    返回:
        str: QP编码结果

    示例:
        >>> encrypt("Hello World")
        'Hello World'
        >>> encrypt("Hello Wörld")
        'Hello W=C3=B6rld'
    """
    try:
        result = quopri.encodestring(plaintext.encode('utf-8'))
        return result.decode('ascii')
    except Exception as e:
        return f"编码错误: {str(e)}"


def decrypt(ciphertext):
    """
    Quoted-Printable解码

    将Quoted-Printable字符串还原为原始字符串。

    参数:
        ciphertext (str): QP编码的字符串

    返回:
        str: 解码后的原始字符串

    示例:
        >>> decrypt("Hello W=C3=B6rld")
        'Hello Wörld'
    """
    try:
        result = quopri.decodestring(ciphertext.encode('ascii'))
        return result.decode('utf-8')
    except Exception as e:
        return f"解码错误: {str(e)}"