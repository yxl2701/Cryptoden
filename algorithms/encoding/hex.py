"""
十六进制编码模块
================

【编码原理】
十六进制(Hex)编码将每个字节(8位)表示为两个十六进制字符(0-9, A-F)。

编码过程:
  1. 将字符串编码为UTF-8字节
  2. 每个字节拆分为高4位和低4位
  3. 每个4位值(0-15)映射为十六进制字符
  4. 可选添加空格或短横线分隔

【特点】
1. 可逆编码，非加密
2. 输出长度为输入的2倍（UTF-8字节数）
3. 人类可读，常用于调试和显示二进制数据

【应用场景】
1. 显示二进制数据（如哈希值、密钥）
2. 调试网络协议
3. CTF中的编码转换

【示例】
  输入: hello
  Hex: 68656C6C6F
  输入: hello (空格分隔)
  Hex: 68 65 6C 6C 6F
"""


def encrypt(plaintext, separator='none'):
    """
    十六进制编码

    将文本编码为十六进制字符串。
    支持三种分隔模式：无分隔、空格分隔、短横线分隔。

    参数:
        plaintext (str): 要编码的原始文本
        separator (str): 分隔符
            - 'none': 无分隔，如 "68656C6C6F"
            - 'space': 空格分隔，如 "68 65 6C 6C 6F"
            - 'dash': 短横线分隔，如 "68-65-6C-6C-6F"

    返回:
        str: 十六进制编码结果（大写）

    示例:
        >>> encrypt("hello")
        '68656C6C6F'
        >>> encrypt("hello", "space")
        '68 65 6C 6C 6F'
    """
    hex_str = plaintext.encode('utf-8').hex().upper()
    if separator == 'space':
        return ' '.join([hex_str[i:i+2] for i in range(0, len(hex_str), 2)])
    elif separator == 'dash':
        return '-'.join([hex_str[i:i+2] for i in range(0, len(hex_str), 2)])
    return hex_str


def _clean_hex(text):
    cleaned = ''.join(text.split()).replace('-', '').replace(':', '')
    if cleaned.lower().startswith('0x'):
        cleaned = cleaned[2:]
    if len(cleaned) % 2:
        raise ValueError('十六进制长度必须为偶数')
    return cleaned


def decrypt(ciphertext):
    """
    十六进制解码

    将十六进制字符串还原为原始文本。
    自动处理空格、短横线和换行符分隔的情况。

    参数:
        ciphertext (str): 十六进制编码的文本

    返回:
        str: 解码后的原始文本

    示例:
        >>> decrypt("68656C6C6F")
        'hello'
        >>> decrypt("68 65 6C 6C 6F")
        'hello'
    """
    try:
        hex_str = _clean_hex(ciphertext)
        return bytes.fromhex(hex_str).decode('utf-8')
    except Exception as e:
        return f"解码错误: {str(e)}"
