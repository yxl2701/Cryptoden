"""
Base32编码模块
==============

【编码原理】
Base32是Base64的变种，使用32个可打印字符(A-Z, 2-7)表示二进制数据。

编码过程:
  1. 将每5个字节(40位)分为一组
  2. 将40位拆分为8个5位组
  3. 每个5位值(0-31)映射到字符表:
     A-Z(0-25), 2-7(26-31)
  4. 末尾用 = 填充到8的倍数

【与Base64的区别】
1. 字符集更小：32个字符 vs 64个字符
2. 编码效率更低：输出比输入多60% vs 33%
3. 不含容易混淆的字符(0/O, 1/I/L等)，适合人工输入

【应用场景】
1. 密钥编码（如TOTP密钥）
2. DNS记录中的二进制数据
3. 需要人工转录的场景

【示例】
  输入: hello
  Base32: NBSWY3DP
"""

ALGORITHM_NAME = "Base32"
ALGORITHM_DESC = "Base32编码，使用32个可打印字符(A-Z, 2-7)表示二进制数据"

import base64


def _clean_base32(text: str) -> str:
    cleaned = ''.join(text.split()).upper()
    if not cleaned:
        return ''
    padding = (-len(cleaned)) % 8
    return cleaned + ('=' * padding)


def encrypt(data: str) -> str:
    """
    Base32编码
    
    将文本编码为Base32格式。
    每5字节→8字符，末尾自动补=。
    
    参数:
        data (str): 要编码的原始文本
    
    返回:
        str: Base32编码结果
    
    示例:
        >>> encrypt("hello")
        'NBSWY3DP'
    """
    try:
        result = base64.b32encode(data.encode()).decode()
        return result
    except Exception:
        return '编码失败'


def decrypt(data: str) -> str:
    """
    Base32解码
    
    将Base32编码还原为原始文本。
    
    参数:
        data (str): Base32编码的文本
    
    返回:
        str: 解码后的原始文本
    
    示例:
        >>> decrypt("NBSWY3DP")
        'hello'
    """
    try:
        result = base64.b32decode(_clean_base32(data).encode(), casefold=True).decode()
        return result
    except Exception as e:
        return f"解码错误: {str(e)}"
