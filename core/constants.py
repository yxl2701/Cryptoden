"""
常量定义模块 (Constants)
========================
定义加解密算法分类的名称、描述和顺序等常量

本模块定义了以下常量:
- CATEGORY_NAMES: 分类中文名称映射表
- CATEGORY_DESC: 分类描述信息映射表
- ENCRYPT_CATEGORIES: 加密算法分类顺序
- DECRYPT_CATEGORIES: 解密算法分类顺序

这些常量用于:
1. 菜单栏中算法分类的显示名称
2. 状态栏中分类的描述信息
3. 算法加载时的分类遍历顺序
"""


# ==================== 分类名称映射表 ====================
# 英文分类名 -> 中文显示名称
CATEGORY_NAMES = {
    'classical': '古典密码',      # 凯撒、ROT13、维吉尼亚、栅栏等传统密码
    'encoding': '编码',           # Base64、Hex、URL、Unicode等编码方式
    'decoding': '解码',           # Base64、Hex、URL、Unicode等解码方式
    'asymmetric': '非对称密码',   # RSA、ECC等非对称加密算法
    'public_key': '公钥密码',     # 公钥基础设施相关算法
    'hash': '哈希',               # MD5、SHA系列等哈希算法
    'symmetric': '对称密码',      # AES、DES、RC4等对称加密算法
    'other': '其他',              # 其他自定义算法
}


# ==================== 分类描述映射表 ====================
# 英文分类名 -> 分类描述（用于状态栏提示）
CATEGORY_DESC = {
    'classical': '凯撒、ROT13、维吉尼亚、栅栏等',
    'encoding': 'Base64、Hex、URL、Unicode等编码方式',
    'decoding': 'Base64、Hex、URL、Unicode等解码方式',
    'hash': 'MD5、SHA系列等哈希算法',
    'symmetric': 'AES、DES、RC4等对称加密算法',
    'asymmetric': 'RSA、ECC等非对称加密算法',
    'public_key': '公钥相关算法',
    'other': '其他自定义算法',
}


# ==================== 加密算法分类顺序 ====================
# 定义加密菜单中分类的显示顺序
# 按照常见使用频率和重要性排序
ENCRYPT_CATEGORIES = [
    'classical',     # 古典密码 - CTF中最常见
    'encoding',      # 编码 - CTF中最常见
    'hash',          # 哈希 - 常见
    'symmetric',     # 对称密码
    'asymmetric',    # 非对称密码
    'public_key',    # 公钥密码
    'other',         # 其他
]


# ==================== 解密算法分类顺序 ====================
# 定义解密菜单中分类的显示顺序
# 注意：解密菜单不包含hash分类（哈希通常不可逆）
DECRYPT_CATEGORIES = [
    'classical',     # 古典密码
    'decoding',      # 解码
    'symmetric',     # 对称密码
    'asymmetric',    # 非对称密码
    'public_key',    # 公钥密码
    'other',         # 其他
]
