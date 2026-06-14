"""
Base91编码模块
==============

【编码原理】
Base91使用91个可打印ASCII字符，编码效率高于Base64。
每13或14位编码为2个字符，平均编码效率约16/18 ≈ 88.9%。

字符集：所有可打印ASCII字符（除 - ' \）

【示例】
  输入: hello
  Base91: >OwJh>Io0
"""

ALGORITHM_NAME = "Base91"
ALGORITHM_DESC = "Base91编码，高编码效率，使用91个可打印ASCII字符"

# Base91字符集
BASE91_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""  # noqa


def _encode_binary(data):
    """将字节数据编码为Base91"""
    if not data:
        return ''

    v = -1
    b = 0
    n = 0
    out = []

    for byte in data:
        b |= (byte << n)
        n += 8
        if n > 13:
            v = b & 8191
            if v > 88:
                b >>= 13
                n -= 13
            else:
                v = b & 16383
                b >>= 14
                n -= 14
            out.append(BASE91_ALPHABET[v % 91])
            out.append(BASE91_ALPHABET[v // 91])

    if n:
        out.append(BASE91_ALPHABET[b % 91])
        if n > 7 or b > 90:
            out.append(BASE91_ALPHABET[b // 91])

    return ''.join(out)


def _decode_binary(data):
    """将Base91字符串解码为字节"""
    if not data:
        return b''

    v = -1
    b = 0
    n = 0
    out = bytearray()

    char_map = {c: i for i, c in enumerate(BASE91_ALPHABET)}

    for c in data:
        if c not in char_map:
            if c.isspace():
                continue
            raise ValueError(f"非法字符: {c!r}")
        c_val = char_map[c]
        if v < 0:
            v = c_val
        else:
            v += c_val * 91
            b |= v << n
            n += 13 if (v & 8191) > 88 else 14
            while n > 7:
                out.append(b & 255)
                b >>= 8
                n -= 8
            v = -1

    if v != -1:
        b |= v << n
        out.append(b & 255)

    return bytes(out)


def encrypt(plaintext):
    """Base91编码"""
    try:
        data = plaintext.encode('utf-8')
        return _encode_binary(data)
    except Exception as e:
        return f"编码错误: {str(e)}"


def decrypt(ciphertext):
    """Base91解码"""
    try:
        data = _decode_binary(ciphertext.strip())
        return data.decode('utf-8')
    except Exception as e:
        return f"解码错误: {str(e)}"
