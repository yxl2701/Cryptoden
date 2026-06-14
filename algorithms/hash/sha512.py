"""
SHA-512哈希模块
===============

【算法介绍】
SHA-512（Secure Hash Algorithm 512）是SHA-2家族的一员，
产生512位(64字节)哈希值，通常用128个十六进制数字表示。
比SHA-256更安全，但计算速度稍慢，在64位系统上反而更快。

【哈希原理】
1. 填充：将数据填充到1024位的倍数
2. 分块：每1024位一块
3. 初始化：8个64位寄存器
4. 处理：80轮压缩函数
5. 输出：512位哈希值

【SHA-2家族对比】
  SHA-224: 224位输出（SHA-256截断版）
  SHA-256: 256位输出（最常用）
  SHA-384: 384位输出（SHA-512截断版）
  SHA-512: 512位输出（最高安全性）

【安全性】
目前没有有效的SHA-512碰撞攻击，推荐用于安全敏感场景。

【示例】
  输入: hello
  SHA-512: 9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890...
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
    SHA-512哈希计算

    计算输入字符串的SHA-512哈希值（512位/128位十六进制）。

    参数:
        plaintext (str): 输入文本

    返回:
        str: 128位十六进制SHA-512哈希值

    示例:
        >>> encrypt("hello")
        '9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890...'
    """
    try:
        return digest(plaintext, 'sha512')
    except Exception as e:
        return f"哈希错误: {str(e)}"
