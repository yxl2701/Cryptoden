"""
批量哈希计算模块
================

【功能介绍】
一次性计算输入文本的多种哈希值，便于对比和选择。
支持的哈希算法：
  - MD5:    128位，32位十六进制（⚠️ 不安全）
  - SHA-1:  160位，40位十六进制（⚠️ 不安全）
  - SHA-256: 256位，64位十六进制（✅ 推荐）
  - SHA-512: 512位，128位十六进制（✅ 最安全）

【应用场景】
1. 对比不同哈希算法的输出长度和格式
2. 快速获取同一文本的多种哈希值
3. 文件完整性交叉验证

【示例】
  输入: hello
  MD5:     5d41402abc4b2a76b9719d911017c592
  SHA-1:   aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
  SHA-256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
  SHA-512: 9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7...
"""

try:
    from .common import digest_many
except ImportError:
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location('hash_common', Path(__file__).with_name('common.py'))
    hash_common = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hash_common)
    digest_many = hash_common.digest_many


HASH_ALGORITHMS = [
    ('MD5', 'md5'),
    ('SHA-1', 'sha1'),
    ('SHA-224', 'sha224'),
    ('SHA-256', 'sha256'),
    ('SHA-384', 'sha384'),
    ('SHA-512', 'sha512'),
    ('SHA3-256', 'sha3_256'),
    ('SHA3-512', 'sha3_512'),
    ('BLAKE2b', 'blake2b'),
    ('BLAKE2s', 'blake2s'),
]

LABEL_WIDTH = max(len(label) for label, _ in HASH_ALGORITHMS)


def encrypt(plaintext):
    """
    批量哈希计算

    同时计算输入文本的MD5、SHA-1、SHA-256、SHA-512哈希值。

    参数:
        plaintext (str): 输入文本

    返回:
        str: 四种哈希值的对比列表

    示例:
        >>> encrypt("hello")
        'MD5:     5d41402abc4b2a76b9719d911017c592\\nSHA-1:   ...'
    """
    try:
        return '\n'.join(
            f"{label + ':':<{LABEL_WIDTH + 2}}{value}"
            for label, value in digest_many(plaintext, HASH_ALGORITHMS)
        )
    except Exception as e:
        return f"哈希错误: {str(e)}"
