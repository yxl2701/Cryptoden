"""
Unicode编码模块
===============

【编码原理】
Unicode编码将字符转换为其Unicode码点(Code Point)的不同表示形式。
每个字符都有一个唯一的Unicode码点(0x0000-0x10FFFF)。

支持的编码格式:
  - Python格式: \\uXXXX (4位十六进制)
  - HTML格式: &#XXXX; (十进制)
  - CSS格式: \\XXXXXX (6位十六进制)

【应用场景】
1. 在源码中安全表示非ASCII字符
2. HTML中的特殊字符转义
3. CSS中的Unicode转义
4. 绕过字符编码限制

【示例】
  输入: 你好
  Python: \\u4F60\\u597D
  HTML: &#20320;&#22909;
  CSS: \\004F60\\00597D
"""

import re


def encrypt(plaintext, format='python'):
    """
    Unicode编码

    将文本中的每个字符转换为其Unicode码点表示。
    支持三种格式：
      - 'python': \\uXXXX (如 \\u4F60)
      - 'html': &#XXXX; (如 &#20320;)
      - 'css': \\XXXXXX (如 \\004F60)

    参数:
        plaintext (str): 要编码的原始文本
        format (str): 编码格式 ('python', 'html', 'css')

    返回:
        str: Unicode编码后的文本

    示例:
        >>> encrypt("A", "python")
        '\\\\u0041'
        >>> encrypt("A", "html")
        '&#65;'
    """
    result = []
    for char in plaintext:
        code = ord(char)
        if format == 'python':
            result.append(f'\\u{code:04X}')
        elif format == 'html':
            result.append(f'&#{code};')
        elif format == 'css':
            result.append(f'\\{code:06X}')
    return ''.join(result)


def decode_python(text):
    """解码Python格式的Unicode转义"""
    return text.encode('utf-8').decode('unicode-escape')


def decode_html(text):
    """解码HTML格式的Unicode实体"""
    import html
    return html.unescape(text)


def decode_css(text):
    """解码CSS格式的Unicode转义"""
    result = []
    i = 0
    while i < len(text):
        if text[i] == '\\' and i + 6 < len(text):
            hex_str = text[i+1:i+7]
            if all(c in '0123456789ABCDEFabcdef' for c in hex_str):
                result.append(chr(int(hex_str, 16)))
                i += 7
                continue
        result.append(text[i])
        i += 1
    return ''.join(result)


def decrypt(ciphertext, format='auto'):
    """
    Unicode解码

    将Unicode编码还原为原始文本。
    'auto' 模式自动检测编码格式。

    参数:
        ciphertext (str): Unicode编码的文本
        format (str): 解码格式 ('auto', 'python', 'html', 'css')

    返回:
        str: 解码后的原始文本

    示例:
        >>> decrypt("\\\\u0041")
        'A'
        >>> decrypt("&#65;")
        'A'
    """
    try:
        if format == 'auto':
            if '\\u' in ciphertext:
                return decode_python(ciphertext)
            elif '&#' in ciphertext:
                return decode_html(ciphertext)
            elif re.search(r'\\[0-9a-fA-F]{6}', ciphertext):
                return decode_css(ciphertext)
            else:
                return ciphertext
        elif format == 'python':
            return decode_python(ciphertext)
        elif format == 'html':
            return decode_html(ciphertext)
        elif format == 'css':
            return decode_css(ciphertext)
        return ciphertext
    except Exception as e:
        return f"解码错误: {str(e)}"