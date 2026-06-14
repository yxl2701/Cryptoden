"""
SHA-1哈希模块
=============

【算法介绍】
SHA-1（Secure Hash Algorithm 1）由NSA设计，产生160位(20字节)哈希值，
通常用40个十六进制数字表示。曾是数字签名标准(DSS)的指定算法。

【哈希原理】
1. 填充：将数据填充到512位的倍数（末尾加1和长度）
2. 分块：每512位一块
3. 初始化：5个32位寄存器(A,B,C,D,E)
4. 处理：80轮压缩函数（4轮×20步）
5. 输出：160位哈希值

【安全性警告】
SHA-1已被证明不安全：
  - 2017年Google和CWI研究所完成SHAttered碰撞攻击
  - 生成两个不同PDF文件具有相同SHA-1哈希
  - 已被Chrome/Firefox等浏览器标记为不安全
  - 推荐使用SHA-256或SHA-512替代

【示例】
  输入: hello
  SHA-1: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
"""

try:
    from .common import digest
except ImportError:
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location('hash_common', Path(__file__).with_name('common.py'))
    hash_common = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hash_common)
    digest = hash_common.digest


def encrypt(plaintext):
    """
    SHA-1哈希计算

    计算输入字符串的SHA-1哈希值（160位/40位十六进制）。

    参数:
        plaintext (str): 输入文本

    返回:
        str: 40位十六进制SHA-1哈希值

    示例:
        >>> encrypt("hello")
        'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'
    """
    try:
        return digest(plaintext, 'sha1')
    except Exception as e:
        return f"哈希错误: {str(e)}"
