"""
Base85编码模块
==============

【编码原理】
Base85（又称Ascii85）是一种将二进制数据编码为可打印ASCII字符的编码方式。
与Base64相比，Base85的编码效率更高（4:5 vs 3:4）。

编码过程：
  1. 将每4个字节（32位）分为一组
  2. 将32位整数转换为85进制（0-84）
  3. 每个85进制位映射到可打印ASCII字符（33-117）

【特点】
1. 编码效率比Base64高（约25%膨胀 vs 33%）
2. 使用更多可打印字符
3. Adobe PostScript和PDF文件中使用

【应用场景】
1. PDF文件中的二进制数据编码
2. PostScript文件
3. CTF编码题

【示例】
  输入: hello
  Base85: BOu!rD]j
"""

ALGORITHM_NAME = "Base85"
ALGORITHM_DESC = "Base85 (Ascii85) 编码，将二进制数据编码为可打印ASCII字符"


def _encode_block(block: bytes) -> str:
    """编码4字节块为5个Base85字符"""
    if len(block) == 0:
        return ''

    # 将字节块转为32位整数（大端序）
    value = 0
    for b in block:
        value = (value << 8) | b

    # 处理短块（不足4字节）：末尾补0
    if len(block) < 4:
        value <<= (8 * (4 - len(block)))

    # 转换为85进制
    result = []
    for _ in range(5):
        result.append(chr(33 + (value % 85)))
        value //= 85

    result.reverse()

    # 如果是短块，截断多余字符（短块输出 len(block)+1 个字符）
    if len(block) < 4:
        return ''.join(result[:len(block) + 1])
    return ''.join(result)


def _decode_block(chars: str) -> bytes:
    """解码Base85字符为字节
    
    5个字符解码为4字节，n个字符（2<=n<5）解码为n-1字节。
    """
    if not chars:
        return b''

    value = 0
    for c in chars:
        if not 33 <= ord(c) <= 117:
            raise ValueError(f"非法字符: {c!r}")
        value = value * 85 + (ord(c) - 33)

    # 处理短块：用最大值（'u'=84）填充到5个字符
    if len(chars) < 5:
        padding = 5 - len(chars)
        for _ in range(padding):
            value = value * 85 + 84

    # 转为4字节
    result = []
    for i in range(4):
        result.append((value >> (24 - i * 8)) & 0xFF)

    # 短块截断：n个字符产生n-1字节
    if len(chars) < 5:
        return bytes(result[:len(chars) - 1])
    return bytes(result)


def encrypt(plaintext):
    """
    Base85编码

    将字符串编码为Base85格式。

    参数:
        plaintext (str): 明文

    返回:
        str: Base85编码结果

    示例:
        >>> encrypt("hello")
        'BOu!rD]j'
    """
    try:
        data = plaintext.encode('utf-8')
        result = []
        for i in range(0, len(data), 4):
            block = data[i:i+4]
            result.append(_encode_block(block))
        return ''.join(result)
    except Exception as e:
        return f"编码错误: {str(e)}"


def decrypt(ciphertext):
    """
    Base85解码

    将Base85字符串还原为原始字符串。

    参数:
        ciphertext (str): Base85编码的字符串

    返回:
        str: 解码后的原始字符串

    示例:
        >>> decrypt("BOu!rD]j")
        'hello'
    """
    try:
        text = ''.join(ciphertext.split())

        if not text:
            return ''
        if len(text) == 1:
            return "解码错误: 数据太短"

        result = []
        for i in range(0, len(text), 5):
            block = text[i:i+5]
            result.append(_decode_block(block))

        return b''.join(result).decode('utf-8')
    except Exception as e:
        return f"解码错误: {str(e)}"
