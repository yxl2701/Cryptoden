"""
Twofish密码模块
================

【加密原理】
Twofish是布鲁斯·施奈尔设计的对称分组密码算法，块大小128位，
支持128/192/256位密钥。它是AES选拔的5个决赛算法之一。

算法结构:
  1. Feistel网络结构，16轮加密
  2. 使用密钥相关的S盒（Key-Dependent S-boxes）
  3. 白化处理（Whitening）：输入输出的异或预处理
  4. 最大距离可分矩阵（MDS Matrix）进行扩散

【与AES的对比】
  - Twofish: Feistel结构，更适合硬件实现
  - AES: SPN结构，软件实现更高效
  - AES最终胜出，但Twofish至今未被破解

【特点】
  - 块大小: 128位
  - 密钥长度: 128/192/256位
  - 轮数: 16轮
  - 安全性: 至今没有有效的攻击方法

【⚠️ 当前实现】
  当前仅提供接口说明，实际加密需要使用pycryptodomex库。
  建议使用AES或Blowfish作为替代。
"""

ALGORITHM_NAME = "Twofish密码"
ALGORITHM_DESC = "AES候选对称密码，Feistel结构128位分组"

# pycryptodomex 提供了 Twofish 支持，但需要额外安装
try:
    from Cryptodome.Cipher import Twofish
    from Cryptodome.Util.Padding import pad, unpad
    TWOFISH_AVAILABLE = True
except ImportError:
    TWOFISH_AVAILABLE = False


def encrypt(plaintext, key):
    """
    Twofish加密

    使用Twofish算法加密数据。
    需要安装 pycryptodomex 库: pip install pycryptodomex

    参数:
        plaintext (str): 明文
        key (str): 密钥（16/24/32字节对应128/192/256位）

    返回:
        str: 加密结果或提示信息
    """
    if TWOFISH_AVAILABLE:
        try:
            key_bytes = key.encode('utf-8')
            cipher = Twofish.new(key_bytes, Twofish.MODE_ECB)
            padded = pad(plaintext.encode('utf-8'), Twofish.block_size)
            encrypted = cipher.encrypt(padded)
            return encrypted.hex()
        except Exception as e:
            return f"Twofish加密错误: {str(e)}"
    return "Twofish需要安装 pycryptodomex 库。\n请使用: pip install pycryptodomex\n或使用AES/Blowfish替代。"


def decrypt(ciphertext, key):
    """
    Twofish解密

    使用Twofish算法解密数据。

    参数:
        ciphertext (str): 十六进制密文
        key (str): 密钥

    返回:
        str: 解密结果或提示信息
    """
    if TWOFISH_AVAILABLE:
        try:
            key_bytes = key.encode('utf-8')
            cipher = Twofish.new(key_bytes, Twofish.MODE_ECB)
            encrypted = bytes.fromhex(ciphertext)
            decrypted = unpad(cipher.decrypt(encrypted), Twofish.block_size)
            return decrypted.decode('utf-8')
        except Exception as e:
            return f"Twofish解密错误: {str(e)}"
    return "Twofish需要安装 pycryptodomex 库。\n请使用: pip install pycryptodomex\n或使用AES/Blowfish替代。"