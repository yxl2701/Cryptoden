"""
SHA-256哈希加密模块
===================

【算法介绍】
SHA-256（Secure Hash Algorithm 256-bit）是SHA-2家族的一员，
由美国国家安全局（NSA）设计，于2001年发布。它产生256位（32字节）
的哈希值，通常用64个十六进制数字表示。

【哈希原理】
SHA-256的处理过程：
1. 填充：将数据填充到512位的倍数
2. 分块：将数据分成512位的块
3. 初始化：设置8个32位的初始哈希值
4. 处理：对每个块进行64轮变换
5. 输出：产生256位的哈希值

【特点】
1. 输出长度固定：256位
2. 安全性高：目前没有有效的碰撞攻击
3. 广泛应用：比特币、SSL/TLS、数字签名等
4. 计算速度适中

【安全性】
SHA-256目前被认为是安全的：
1. 尚未发现实际可行的碰撞攻击
2. 推荐用于安全敏感场景
3. 比特币等加密货币使用SHA-256

【示例】
输入：hello
SHA-256：2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824

【应用场景】
1. 数字签名
2. 密码存储
3. 区块链
4. SSL/TLS证书
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
    SHA-256哈希函数
    
    计算输入字符串的SHA-256哈希值。
    
    参数:
        plaintext (str): 输入文本
    
    返回:
        str: 64位十六进制SHA-256哈希值
    
    示例:
        >>> encrypt("hello")
        '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
    """
    try:
        return digest(plaintext, 'sha256')
    except Exception as e:
        return f"哈希错误: {str(e)}"
