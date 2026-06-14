"""
核心模块
========
包含加解密算法加载器、常量定义等核心功能
"""

from .constants import CATEGORY_NAMES, CATEGORY_DESC
from .crypto_loader import CryptoLoader

__all__ = ['CATEGORY_NAMES', 'CATEGORY_DESC', 'CryptoLoader']
