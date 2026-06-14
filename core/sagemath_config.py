"""
SageMath配置管理模块
====================
管理SageMath解释器的配置信息

功能:
- 保存和加载SageMath路径配置
- 支持本机路径和WSL路径
- 支持SageCell网页端在线运行
- 自动检测已安装的SageMath
"""

import json
import os
import shutil
from pathlib import Path
from typing import Optional, Dict, Any


class SageMathConfig:
    """
    SageMath配置管理类
    
    管理SageMath解释器的路径配置，支持:
    - 本机Windows路径
    - WSL路径
    - 自动检测已安装的SageMath
    """
    
    DEFAULT_CONFIG = {
        'sage_type': 'wsl',
        'local_path': '',
        'wsl_distro': 'Ubuntu',
        'wsl_path': '/usr/bin/sage',
        'online_url': 'https://sagecell.sagemath.org/',
        'auto_detect': True
    }
    
    CONFIG_FILE = 'sagemath_config.json'
    
    def __init__(self, base_path: Optional[Path] = None):
        """
        初始化配置管理器
        
        参数:
            base_path: 配置文件保存路径，默认为当前模块所在目录
        """
        if base_path is None:
            base_path = Path(__file__).parent.parent
        self.config_path = base_path / self.CONFIG_FILE
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """
        从文件加载配置
        
        返回:
            配置字典
        """
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    loaded = json.load(f)
                    config = self.DEFAULT_CONFIG.copy()
                    config.update(loaded)
                    return config
            except (json.JSONDecodeError, IOError):
                pass
        return self.DEFAULT_CONFIG.copy()
    
    def save_config(self) -> bool:
        """
        保存配置到文件
        
        返回:
            是否保存成功
        """
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            return True
        except IOError:
            return False
    
    def get_sage_type(self) -> str:
        """获取SageMath类型: 'local'、'wsl' 或 'online'"""
        return self.config.get('sage_type', 'local')
    
    def set_sage_type(self, sage_type: str):
        """设置SageMath类型"""
        self.config['sage_type'] = sage_type
    
    def get_local_path(self) -> str:
        """获取本机SageMath路径"""
        return self.config.get('local_path', '')
    
    def set_local_path(self, path: str):
        """设置本机SageMath路径"""
        self.config['local_path'] = path
    
    def get_wsl_distro(self) -> str:
        """获取WSL发行版名称"""
        return self.config.get('wsl_distro', 'Ubuntu')
    
    def set_wsl_distro(self, distro: str):
        """设置WSL发行版名称"""
        self.config['wsl_distro'] = distro
    
    def get_wsl_path(self) -> str:
        """获取WSL中SageMath路径"""
        return self.config.get('wsl_path', '/usr/bin/sage')
    
    def set_wsl_path(self, path: str):
        """设置WSL中SageMath路径"""
        self.config['wsl_path'] = path

    def get_online_url(self) -> str:
        """获取SageCell在线运行地址"""
        return self.config.get('online_url', 'https://sagecell.sagemath.org/')

    def set_online_url(self, url: str):
        """设置SageCell在线运行地址"""
        self.config['online_url'] = url
    
    def get_executable_command(self) -> Optional[str]:
        """
        获取SageMath可执行命令
        
        返回:
            可执行的命令字符串，如果未配置则返回None
        """
        sage_type = self.get_sage_type()
        
        if sage_type == 'local':
            local_path = self.get_local_path()
            if local_path:
                return local_path
        elif sage_type == 'wsl':
            distro = self.get_wsl_distro()
            wsl_path = self.get_wsl_path()
            if distro and wsl_path:
                return f'wsl -d {distro} {wsl_path}'
        elif sage_type == 'online':
            return self.get_online_url().strip() or None
        
        return None
    
    def is_configured(self) -> bool:
        """检查是否已配置SageMath"""
        return self.get_executable_command() is not None
    
    def validate_local_path(self, path: str) -> bool:
        """
        验证本机SageMath路径是否有效
        
        参数:
            path: SageMath路径
            
        返回:
            路径是否有效
        """
        if not path:
            return False
        
        sage_path = Path(path)
        
        if sage_path.exists() and sage_path.is_file():
            return True
        
        return False
    
    @staticmethod
    def detect_local_installations() -> list:
        """
        自动检测本机已安装的SageMath
        
        返回:
            检测到的SageMath路径列表
        """
        detected = []
        for executable in ('sage', 'sage.exe'):
            found = shutil.which(executable)
            if found and found not in detected:
                detected.append(found)

        search_paths = []
        for env_name in ('PROGRAMFILES', 'PROGRAMFILES(X86)', 'LOCALAPPDATA'):
            env_path = os.environ.get(env_name)
            if env_path:
                search_paths.append(Path(env_path))

        home = Path.home()
        search_paths.extend([home, home.parent])
        
        for base in search_paths:
            if not base.exists():
                continue
            
            try:
                for item in base.iterdir():
                    if 'sage' in item.name.lower():
                        if item.is_dir():
                            for sage_file in item.rglob('sage'):
                                if sage_file.is_file():
                                    detected.append(str(sage_file))
                                    break
                            for sage_exe in item.rglob('sage.exe'):
                                if sage_exe.is_file():
                                    detected.append(str(sage_exe))
            except (PermissionError, OSError):
                continue
        
        return detected


sage_config = SageMathConfig()
