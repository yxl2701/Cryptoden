"""
一键解密模块
============
实现一键解密功能，范围为加解密文件夹中的加解密算法，不包含复杂的密码学算法。

功能:
- 遍历所有解密算法尝试解密
- 优先使用decrypt_all爆破函数
- 返回所有成功的解密结果
"""

from typing import List, Dict, Optional
from pathlib import Path
import importlib.util


class OneClickDecryptor:
    """
    一键解密器类
    
    遍历所有解密算法，尝试解密输入文本。
    """
    
    def __init__(self, base_path: Path):
        """
        初始化一键解密器
        
        参数:
            base_path: 程序基础路径
        """
        self.base_path = base_path
        self.decrypt_path = base_path / "algorithms"
        self.decrypt_modules = {}
        self.load_modules()
        
    def load_module_from_file(self, file_path: Path) -> Optional[object]:
        """
        从文件路径动态加载Python模块
        
        参数:
            file_path: 模块文件路径
            
        返回:
            加载的模块对象，失败返回None
        """
        try:
            spec = importlib.util.spec_from_file_location(file_path.stem, file_path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                return module
        except Exception:
            pass
        return None
        
    def load_modules(self):
        """加载所有解密模块"""
        self.decrypt_modules.clear()
        
        if not self.decrypt_path.exists():
            return
            
        for category_dir in self.decrypt_path.iterdir():
            if category_dir.is_dir() and not category_dir.name.startswith("_"):
                for py_file in category_dir.glob("*.py"):
                    if not py_file.name.startswith("_"):
                        module = self.load_module_from_file(py_file)
                        if module and hasattr(module, 'algorithms'):
                            algo_name = getattr(module, 'ALGORITHM_NAME', py_file.stem)
                            self.decrypt_modules[algo_name] = module
                            
    def decrypt_all(self, ciphertext: str) -> List[Dict]:
        """
        一键解密
        
        尝试所有解密算法解密输入文本。
        
        参数:
            ciphertext: 密文
            
        返回:
            解密结果列表，每个元素包含:
            - name: 算法名称
            - result: 解密结果
            - success: 是否成功
            - brute_force: 是否使用爆破方式
        """
        results = []
        
        for algo_name, module in self.decrypt_modules.items():
            try:
                if hasattr(module, 'decrypt_all'):
                    result = module.decrypt_all(ciphertext)
                    if result:
                        results.append({
                            'name': algo_name,
                            'result': str(result),
                            'success': True,
                            'brute_force': True
                        })
                        
                if hasattr(module, 'algorithms'):
                    result = module.decrypt(ciphertext)
                    if result and result != ciphertext:
                        results.append({
                            'name': algo_name,
                            'result': str(result),
                            'success': True,
                            'brute_force': False
                        })
            except Exception:
                pass
                
        return results


def decrypt_all(ciphertext: str, base_path: Path = None) -> List[Dict]:
    """
    一键解密函数
    
    参数:
        ciphertext: 密文
        base_path: 程序基础路径（可选）
        
    返回:
        解密结果列表
    """
    if base_path is None:
        base_path = Path(__file__).parent
        
    decryptor = OneClickDecryptor(base_path)
    return decryptor.decrypt_all(ciphertext)

