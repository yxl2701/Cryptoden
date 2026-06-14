"""
加解密模块加载器 (Crypto Loader)
================================
动态加载 algorithms/ 目录下的算法模块

本模块提供以下功能:
- 动态扫描并加载算法模块文件
- 按分类组织算法模块
- 提供统一的加解密执行接口
- 支持一键解密（尝试所有解密算法）

算法模块规范:
每个算法模块(.py文件)应包含以下可选属性:
- ALGORITHM_NAME: 算法显示名称（默认使用文件名）
- ALGORITHM_DESC: 算法描述信息
- PARAMS: 参数定义列表（用于动态生成参数面板）
- encrypt()/decrypt(): 加密/解密函数
- decrypt_all(): 爆破解密函数（可选）

使用示例:
    loader = CryptoLoader(Path(__file__).parent)
    loader.load_all_modules()
    
    result = loader.execute_encrypt('caesar', 'hello', shift=3)
    result = loader.execute_decrypt('caesar', 'khoor', shift=3)
"""

import importlib.util
import inspect
import re
from pathlib import Path
from typing import Dict, Any, Optional, List

from .constants import CATEGORY_NAMES, CATEGORY_DESC


class CryptoLoader:
    """
    加解密算法模块加载器类
    
    负责动态加载 algorithms/ 目录下的算法模块，
    并提供统一的加解密执行接口。
    """
    
    def __init__(self, base_path: Path):
        self.base_path = base_path
        self.algorithms_path = base_path / "algorithms"
        self.encrypt_modules: Dict[str, Any] = {}
        self.decrypt_modules: Dict[str, Any] = {}
        
    def load_module_from_file(self, file_path: Path) -> Optional[Any]:
        try:
            spec = importlib.util.spec_from_file_location(file_path.stem, file_path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                return module
        except Exception:
            pass
        return None
        
    def load_all_modules(self) -> Dict[str, int]:
        self.encrypt_modules.clear()
        self.decrypt_modules.clear()
        
        self._load_all_algorithms()
        
        return {
            'encrypt': len(self.encrypt_modules),
            'decrypt': len(self.decrypt_modules)
        }
    
    def _load_all_algorithms(self):
        """从 algorithms/ 目录加载所有算法"""
        if not self.algorithms_path.exists():
            return
        
        for category_dir in sorted(self.algorithms_path.iterdir()):
            if not category_dir.is_dir() or category_dir.name.startswith('_'):
                continue
            
            category = category_dir.name
            self._load_category(category_dir, category)
    
    def _load_category(self, cat_path: Path, category: str):
        """加载单个分类目录下的算法"""
        for item in sorted(cat_path.iterdir()):
            if item.name.startswith('_') or item.name.startswith('.'):
                continue
            
            if item.is_file() and item.suffix == '.py':
                self._load_single_module(item, category)
            
            elif item.is_dir() and item.name not in ('attacks', '__pycache__'):
                # 子目录（如 asymmetric/rsa/）
                for py_file in sorted(item.glob("*.py")):
                    if not py_file.name.startswith('_'):
                        self._load_single_module(py_file, category)
    
    def _load_single_module(self, py_file: Path, category: str) -> Optional[Dict]:
        module = self.load_module_from_file(py_file)
        if not module:
            return None
        
        algo_name = getattr(module, 'ALGORITHM_NAME', py_file.stem)
        algo_desc = getattr(module, 'ALGORITHM_DESC', '')
        params = getattr(module, 'PARAMS', None)
        
        has_encrypt = hasattr(module, 'encrypt')
        has_decrypt = hasattr(module, 'decrypt')
        
        module_info = {
            'module': module,
            'name': algo_name,
            'desc': algo_desc,
            'params': params,
            'file_path': py_file,
            'category': category,
        }
        
        if has_encrypt:
            self.encrypt_modules[algo_name] = module_info
        if has_decrypt:
            self.decrypt_modules[algo_name] = module_info
        
        return module_info
    
    def get_module_info(self, algo_name: str, mode: str) -> Optional[Dict]:
        module_dict = self.encrypt_modules if mode == 'encrypt' else self.decrypt_modules
        return module_dict.get(algo_name)
    
    def get_all_algo_names(self, mode: str) -> List[str]:
        module_dict = self.encrypt_modules if mode == 'encrypt' else self.decrypt_modules
        return list(module_dict.keys())
    
    def _map_text_param(self, func, input_text: str) -> dict:
        """将 input_text 映射到函数实际的参数名"""
        try:
            sig = inspect.signature(func)
            for param_name in sig.parameters.keys():
                if param_name.lower() in ('plaintext', 'ciphertext', 'cryptotext', 'text',
                                          'input_text', 'message', 'msg', 'input', 'data'):
                    return {param_name: input_text}
        except Exception:
            pass
        return {'text': input_text}
    
    def execute_encrypt(self, algo_name: str, input_text: str, **kwargs) -> Optional[str]:
        info = self.encrypt_modules.get(algo_name)
        if not info:
            return None
        
        module = info['module']
        try:
            if hasattr(module, 'encrypt'):
                text_kwargs = self._map_text_param(module.encrypt, input_text)
                return module.encrypt(**text_kwargs, **kwargs)
        except Exception as e:
            raise e
        return None
    
    def execute_decrypt(self, algo_name: str, input_text: str, **kwargs) -> Optional[str]:
        info = self.decrypt_modules.get(algo_name)
        if not info:
            return None
        
        module = info['module']
        try:
            if hasattr(module, 'decrypt'):
                text_kwargs = self._map_text_param(module.decrypt, input_text)
                return module.decrypt(**text_kwargs, **kwargs)
        except Exception as e:
            raise e
        return None
    
    def try_decrypt_all(
        self,
        input_text: str,
        filter_errors: bool = True,
        match_patterns: Optional[List[str]] = None,
    ) -> List[Dict]:
        """
        尝试所有解密算法进行解密（一键解密）
        
        参数:
            input_text: 要解密的文本
            filter_errors: 是否过滤掉明显是错误信息的结果
            match_patterns: 用于结果排序的关键词
        
        返回:
            list: 解密结果列表，每个元素为 {'name': 算法名, 'result': 结果}
        """
        results = []
        seen = set()

        def add_result(algo_name: str, result, is_brute: bool = False, params: str = ""):
            if result is None:
                return
            result_str = str(result)
            if result_str == input_text:
                return
            if filter_errors and self._is_error_result(result_str):
                return
            key = (algo_name, result_str, params if is_brute else "")
            if key in seen:
                return
            seen.add(key)
            results.append({
                'name': algo_name,
                'result': result,
                'success': True,
                'is_brute': is_brute,
                'params': params,
                'score': self._score_result(result_str, match_patterns),
            })

        def add_bruteforce_results(algo_name: str, output):
            for params, candidate in self._parse_decrypt_all_output(output):
                add_result(algo_name, candidate, is_brute=True, params=params)

        for algo_name, info in self.decrypt_modules.items():
            module = info['module']
            try:
                if hasattr(module, 'decrypt'):
                    text_kwargs = self._map_text_param(module.decrypt, input_text)
                    add_result(algo_name, module.decrypt(**text_kwargs))
            except Exception:
                pass
            try:
                if hasattr(module, 'decrypt_all'):
                    text_kwargs = self._map_text_param(module.decrypt_all, input_text)
                    add_bruteforce_results(algo_name, module.decrypt_all(**text_kwargs))
            except Exception:
                pass
        results.sort(key=lambda item: (-item.get('score', 0), len(str(item.get('result', '')))))
        return results

    @staticmethod
    def _parse_decrypt_all_output(output) -> List[tuple]:
        """Split small-keyspace brute-force output into individual candidates."""
        candidates = []
        seen = set()
        for raw_line in str(output).splitlines():
            line = raw_line.strip()
            if not line:
                continue
            params = "爆破"
            candidate = line
            match = re.match(r'^(偏移量|shift)\s*([0-9]+)\s*[:：]\s*(.*)$', line, re.IGNORECASE)
            if match:
                params = f"shift={match.group(2)}"
                candidate = match.group(3).strip()
            elif ':' in line or '：' in line:
                sep = ':' if ':' in line else '：'
                params, candidate = [part.strip() for part in line.split(sep, 1)]
            key = (params, candidate)
            if candidate and key not in seen:
                seen.add(key)
                candidates.append((params, candidate))
        return candidates

    @staticmethod
    def _is_error_result(result_str: str) -> bool:
        """判断解密结果是否为错误信息"""
        if not result_str:
            return True
        error_indicators = ('错误:', '解码失败', '解码错误', '失败:', '???', '?')
        stripped = result_str.strip()
        return any(stripped.startswith(ind) for ind in error_indicators) or stripped in ('', '?')

    @staticmethod
    def _score_result(result_str: str, match_patterns: Optional[List[str]] = None) -> int:
        """给一键解密结果打分，让明显可读或命中关键词的结果优先显示。"""
        score = 0
        text_lower = result_str.lower()
        for pattern in match_patterns or ('flag', 'ctf', 'key'):
            pattern = str(pattern).strip().lower()
            if pattern and pattern in text_lower:
                score += 50

        if re.search(r"flag\s*\{[^}]{3,}\}", result_str, re.IGNORECASE):
            score += 120
        if re.search(r"ctf\s*\{[^}]{3,}\}", result_str, re.IGNORECASE):
            score += 100
        if "{" in result_str and "}" in result_str:
            score += 15

        printable = sum(1 for ch in result_str if ch.isprintable() or ch in '\r\n\t')
        printable_ratio = printable / max(1, len(result_str))
        if printable_ratio > 0.92:
            score += 20
        stripped = result_str.strip()
        if 4 <= len(stripped) <= 300:
            score += 10
        if stripped.isascii():
            score += 5
        common_words = re.findall(r'\b(the|and|you|that|have|for|not|with|this|hello|world|admin|root|flag|secret|password)\b', text_lower)
        score += min(80, len(common_words) * 35)
        letters_or_space = sum(1 for ch in stripped if ch.isalpha() or ch.isspace())
        if letters_or_space / max(1, len(stripped)) > 0.8 and ' ' in stripped:
            score += 20

        if any(marker in result_str for marker in ("错误", "失败", "解码错误", "???")):
            score -= 80
        return score
    
    def get_categories(self) -> List[str]:
        """获取所有分类名称"""
        categories = []
        if self.algorithms_path.exists():
            for d in sorted(self.algorithms_path.iterdir()):
                if d.is_dir() and not d.name.startswith('_'):
                    categories.append(d.name)
        return categories
