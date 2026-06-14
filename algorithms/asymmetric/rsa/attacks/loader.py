"""
RSA攻击模块加载器
================
动态加载attacks目录下的攻击模块
"""

from pathlib import Path
from algorithms.asymmetric.base_loader import BaseAttackLoader


class RSALoader(BaseAttackLoader):
    """RSA攻击模块加载器"""
    
    def __init__(self, base_path: Path = None):
        attacks_path = Path(__file__).parent
        super().__init__(attacks_path)
