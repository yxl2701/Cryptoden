"""
MD5哈希加密模块
===============

【算法介绍】
MD5（Message-Digest Algorithm 5）是一种广泛使用的密码散列函数，
由Ronald Rivest于1991年设计。它可以产生128位（16字节）的哈希值，
通常用32个十六进制数字表示。

【哈希原理】
MD5将任意长度的输入数据处理为固定长度的输出：
1. 填充：将数据填充到512位的倍数
2. 分块：将数据分成512位的块
3. 处理：对每个块进行4轮变换
4. 输出：产生128位的哈希值

【特点】
1. 固定输出长度：无论输入多长，输出都是128位
2. 单向性：无法从哈希值反推原始数据
3. 雪崩效应：输入微小变化，输出完全不同
4. 快速计算：设计用于快速计算

【安全性警告】
MD5已被证明不安全：
1. 2004年发现碰撞攻击方法
2. 可伪造数字签名
3. 不应用于安全敏感场景
4. 仅用于数据校验、非安全目的

【示例】
输入：hello
MD5：5d41402abc4b2a76b9719d911017c592

输入：Hello
MD5：8b1a9953c4611296a827abf8c47804d7

【应用场景】
1. 文件完整性校验
2. 密码存储（不推荐）
3. 数据去重
"""

ALGORITHM_NAME = "MD5"
ALGORITHM_DESC = "MD5哈希算法，生成128位哈希值"

PARAMS = []

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
    MD5哈希函数
    
    计算输入字符串的MD5哈希值。
    
    参数:
        plaintext (str): 输入文本
    
    返回:
        str: 32位十六进制MD5哈希值
    
    计算过程:
        1. 将字符串编码为UTF-8字节
        2. 创建MD5哈希对象
        3. 计算哈希值
        4. 转换为十六进制字符串
    
    示例:
        >>> encrypt("hello")
        '5d41402abc4b2a76b9719d911017c592'
    """
    try:
        return digest(plaintext, 'md5')
    except Exception as e:
        return f"哈希错误: {str(e)}"
