"""
攻击模块基础加载器
==================
提供攻击模块动态加载的通用功能
"""

import importlib.util
from pathlib import Path
from typing import Dict, Any, Optional, List


class BaseAttackLoader:
    """攻击模块加载器基类"""
    
    def __init__(self, attacks_path: Path = None):
        self.attacks_path = Path(attacks_path) if attacks_path else Path(__file__).parent
        self.attack_modules: Dict[str, Dict] = {}
        self._loaded = False
    
    def load_module_from_file(self, file_path: Path) -> Optional[Any]:
        """从文件路径动态加载Python模块"""
        try:
            spec = importlib.util.spec_from_file_location(file_path.stem, file_path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                return module
        except Exception as e:
            print(f"加载模块失败 {file_path}: {e}")
        return None
    
    def load_all_attacks(self) -> Dict[str, int]:
        """加载所有攻击模块"""
        if not self.attacks_path.exists():
            return {'attacks': 0}
        
        for py_file in sorted(self.attacks_path.glob("*_attack.py")):
            if not py_file.name.startswith("_"):
                self._load_single_attack(py_file)
                
        return {'attacks': len(self.attack_modules)}
    
    def _load_single_attack(self, py_file: Path) -> Optional[Dict]:
        """加载单个攻击模块"""
        module = self.load_module_from_file(py_file)
        if not module:
            return None
        
        if not hasattr(module, 'attack'):
            return None
        
        attack_name = getattr(module, 'ATTACK_NAME', py_file.stem)
        attack_desc = getattr(module, 'ATTACK_DESC', '')
        attack_hint = getattr(module, 'ATTACK_HINT', '')
        input_fields = getattr(module, 'INPUT_FIELDS', [])
        
        self.attack_modules[attack_name] = {
            'module': module,
            'name': attack_name,
            'desc': attack_desc,
            'hint': attack_hint,
            'input_fields': input_fields,
            'file_path': py_file
        }
        
        return self.attack_modules[attack_name]
    
    def get_attack_names(self) -> List[str]:
        """获取所有攻击名称"""
        if not self._loaded:
            self.load_all_attacks()
            self._loaded = True
        return list(self.attack_modules.keys())
    
    def get_attack_info(self, attack_name: str) -> Optional[Dict]:
        """获取攻击信息"""
        return self.attack_modules.get(attack_name)
    
    def execute_attack(self, attack_name: str, **kwargs) -> Any:
        """执行攻击，返回原始结果"""
        info = self.attack_modules.get(attack_name)
        if not info:
            return {'success': False, 'text': f"未找到攻击模块: {attack_name}"}
        
        module = info['module']
        try:
            result = module.attack(**kwargs)
            if isinstance(result, str):
                if "成功" in result:
                    return {'success': True, 'text': result}
                return {'success': False, 'text': result}
            return result
        except Exception as e:
            return {'success': False, 'text': f"攻击执行错误: {str(e)}"}
    
    def parse_attack_result(self, result) -> Dict:
        """解析攻击结果，统一返回dict格式"""
        if isinstance(result, dict):
            return result
        if isinstance(result, str):
            if "成功" in result:
                return {'success': True, 'text': result}
            return {'success': False, 'text': result}
        return {'success': False, 'text': str(result)}
