"""
CTF加解密工具 (Cryptoden)
=========================
用于CTF比赛中的各种加解密操作

功能特点:
- 动态加载加解密算法模块（从algorithms/文件夹自动加载）
- 根据算法参数动态生成输入界面（自动识别函数签名）
- 支持多种密码类型分类（古典密码、编码、哈希、对称/非对称密码等）
- 提供文本转换和格式处理功能
- 可自定义界面颜色和字体
- 支持一键解密（尝试所有解密算法）
- 支持历史记录撤销/重做

项目结构:
├── main.py              - 程序入口文件（本文件）
├── algorithms/          - 算法模块目录
│   ├── classical/       - 古典密码（凯撒、维吉尼亚、栅栏等）
│   ├── encoding/        - 编码算法（Base64、Hex等）
│   ├── hash/            - 哈希算法（MD5、SHA等）
│   ├── symmetric/       - 对称密码（AES、DES、RC4等）
│   └── asymmetric/      - 非对称密码（RSA、ECC、LCG）
├── core/                - 核心功能模块
│   ├── constants.py     - 常量定义
│   ├── crypto_loader.py - 统一算法加载器
│   ├── sage_executor.py - SageMath 执行器
│   └── sagemath_config.py - SageMath 配置
├── gui/                 - 图形界面模块
│   ├── main_window.py   - 主窗口实现
│   └── settings_dialog.py - 设置对话框
└── utils/               - 工具模块
    └── history.py       - 历史记录管理器

作者: Cryptoden Team
版本: 1.0.0
"""

import sys
import os
from pathlib import Path


def setup_path():
    """
    固定 sys.path，确保 import 路径稳定
    不管从哪个目录启动，都能正确找到模块
    """
    # 获取当前文件所在目录（即项目根目录）
    project_root = Path(__file__).parent.resolve()
    
    # 将项目根目录加入 sys.path（如果不在其中）
    root_str = str(project_root)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)
    
    # 将 algorithms 目录加入 sys.path（方便直接 import）
    algo_path = str(project_root / "algorithms")
    if algo_path not in sys.path:
        sys.path.insert(0, algo_path)
    
    return project_root


def main():
    """
    程序主入口函数
    
    创建QApplication实例，初始化主窗口，启动事件循环。
    这是整个应用程序的启动点。
    """
    project_root = setup_path()
    from utils.logging_config import install_excepthook, setup_logging
    setup_logging()
    install_excepthook(show_dialog=True)
    
    from PyQt5.QtGui import QIcon
    from PyQt5.QtWidgets import QApplication
    from gui import CryptoTool
    
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    icon_path = project_root / "cryptoden_icon.png"
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))
    
    window = CryptoTool()
    window.show()
    
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
