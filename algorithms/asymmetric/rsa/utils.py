"""
RSA工具函数模块
===============
提供RSA相关的辅助函数
"""

import math
import random
import base64


def extended_gcd(a, b):
    """扩展欧几里得算法"""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    return gcd, y1 - (b // a) * x1, x1


def mod_inverse(e, phi):
    """计算模逆元"""
    gcd, x, _ = extended_gcd(e % phi, phi)
    if gcd != 1:
        return None
    return (x % phi + phi) % phi


def is_prime(n, k=5):
    """Miller-Rabin素性测试"""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits):
    """生成指定位数的素数"""
    while True:
        n = random.getrandbits(bits)
        n |= (1 << bits - 1) | 1
        if is_prime(n):
            return n


def next_prime(n):
    """返回大于等于n的下一个素数"""
    if n <= 2:
        return 2
    if n % 2 == 0:
        n += 1
    else:
        n += 2
    while not is_prime(n):
        n += 2
    return n


def integer_nth_root(x, n):
    """计算整数n次根"""
    if x < 0:
        return None
    if x == 0:
        return 0
    
    low, high = 0, x
    while low < high:
        mid = (low + high + 1) // 2
        if mid ** n <= x:
            low = mid
        else:
            high = mid - 1
    
    if low ** n == x:
        return low
    return None


def format_value(val, output_format):
    """格式化数值输出"""
    import base64
    
    if val is None:
        return ""
    
    if isinstance(val, bytes):
        if output_format == "decimal":
            return str(int.from_bytes(val, 'big'))
        elif output_format == "base64":
            return base64.b64encode(val).decode()
        elif output_format == "hex":
            return val.hex()
        return base64.b64encode(val).decode()
    
    if output_format == "decimal":
        return str(val)
    elif output_format == "base64":
        byte_length = (val.bit_length() + 7) // 8
        return base64.b64encode(val.to_bytes(byte_length, 'big')).decode()
    elif output_format == "hex":
        return hex(val)
    return str(val)


def parse_input_value(text):
    """解析输入值，支持十进制、十六进制、Base64"""
    text = text.strip()
    if not text:
        return None
    
    try:
        if text.startswith('0x') or text.startswith('0X'):
            return int(text, 16)
        elif text.startswith('-----BEGIN'):
            return None
        try:
            return int(text)
        except ValueError:
            cleaned = ''.join(text.split())
            cleaned += '=' * ((-len(cleaned)) % 4)
            decoded = base64.b64decode(cleaned, validate=True)
            return int.from_bytes(decoded, 'big')
    except Exception:
        return None


def decode_plaintext(m):
    """将整数转换为明文字符串"""
    if m == 0:
        return ""
    byte_length = (m.bit_length() + 7) // 8
    try:
        return m.to_bytes(byte_length, 'big').decode('utf-8', errors='replace')
    except:
        return f"(无法解码为UTF-8，十六进制: {hex(m)})"
