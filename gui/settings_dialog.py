"""
设置对话框模块 (Settings Dialog)
================================
提供用户自定义设置的界面

本模块包含:
- SettingsDialog: 设置对话框类，提供常规、字体、颜色三个设置选项卡

功能特点:
- 常规设置：自动复制、自动交换、自动换行
- 字体设置：字体选择、大小调整
- 颜色设置：界面各元素颜色自定义
- 支持实时预览和恢复默认值
"""

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTabWidget, QWidget,
    QGroupBox, QCheckBox, QLabel, QPushButton, QSpinBox,
    QScrollArea, QFrame, QRadioButton, QLineEdit, QTextEdit, QFileDialog,
    QButtonGroup, QMessageBox, QComboBox, QDoubleSpinBox
)
from PyQt5.QtGui import QFont, QColor
from PyQt5.QtWidgets import QFontDialog, QColorDialog
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from pathlib import Path

from core.sagemath_config import sage_config
from agent.config import AgentConfig
from utils.ai_assistant import AIConfig, AIClient
from utils.recursive_features import normalize_custom_features
from .ai_config_dialog import ModelFetchWorker
from .algorithm_tabs import load_algorithm_tab_defs


class SettingsDialog(QDialog):
    """
    设置对话框类
    
    提供用户自定义设置的界面，包含三个选项卡：
    - 常规：自动化选项和文本显示设置
    - 字体：字体选择和大小调整
    - 颜色：界面各元素颜色自定义
    
    属性:
        parent_window: 父窗口引用，用于读取和修改主窗口设置
        auto_copy_check: 自动复制复选框
        auto_swap_check: 自动交换复选框
        wrap_check: 自动换行复选框
        font_label: 当前字体显示标签
        font_size_spin: 字体大小调节器
        各颜色属性和按钮...
    """
    
    def __init__(self, parent=None):
        """
        初始化设置对话框
        
        参数:
            parent: 父窗口（CryptoTool实例），用于获取和修改主窗口的设置
        """
        super().__init__(parent)
        self.parent_window = parent          # 保存父窗口引用
        self.crypto_panel = getattr(parent, 'crypto_panel', parent)
        self.agent_config = AgentConfig()
        self.algorithm_tab_defs = load_algorithm_tab_defs(getattr(parent, 'base_path', None) or Path(__file__).parent.parent)
        self.setWindowTitle("设置")
        self.setMinimumSize(650, 450)         # 设置对话框最小尺寸
        self.setup_ui()                       # 构建界面
        
    def setup_ui(self):
        """
        构建设置对话框的界面
        
        创建选项卡容器，分别添加常规、字体、颜色三个选项卡，
        最后添加确定、取消、应用按钮。
        """
        layout = QVBoxLayout(self)            # 主布局使用垂直布局
        tabs = QTabWidget()                   # 创建选项卡容器
        layout.addWidget(tabs)
        
        self._setup_general_tab(tabs)         # 常规选项卡
        self._setup_font_tab(tabs)            # 字体选项卡
        self._setup_color_tab(tabs)           # 颜色选项卡
        self._setup_sagemath_tab(tabs)        # SageMath选项卡
        self._setup_ai_tab(tabs)              # AI配置选项卡
        self._setup_agent_tab(tabs)           # Agent选项卡
        self._setup_algorithm_tabs_tab(tabs)  # 算法选项卡
        self._setup_buttons(layout)           # 底部按钮
        
    def _setup_general_tab(self, tabs: QTabWidget):
        """
        设置常规选项卡
        
        包含自动化选项和文本显示设置：
        - 自动复制：操作完成后自动复制结果到剪贴板
        - 自动交换：操作完成后自动将结果移至输入框
        - 自动换行：切换文本自动换行显示
        
        参数:
            tabs: 选项卡容器，用于添加此选项卡
        """
        general_tab = QWidget()               # 创建选项卡页面
        general_layout = QVBoxLayout(general_tab)
        
        # ==================== 自动化选项分组 ====================
        auto_group = QGroupBox("自动化选项")
        auto_layout = QVBoxLayout(auto_group)
        
        # 自动复制复选框 - 从父窗口读取当前设置
        self.auto_copy_check = QCheckBox("操作完成后自动复制结果到剪贴板")
        self.auto_copy_check.setChecked(getattr(self.crypto_panel, 'auto_copy', False))
        auto_layout.addWidget(self.auto_copy_check)
        
        # 自动交换复选框
        self.auto_swap_check = QCheckBox("操作完成后自动交换输入输出")
        self.auto_swap_check.setChecked(getattr(self.crypto_panel, 'auto_swap', False))
        auto_layout.addWidget(self.auto_swap_check)
        
        general_layout.addWidget(auto_group)
        
        # ==================== 文本显示分组 ====================
        wrap_group = QGroupBox("文本显示")
        wrap_layout = QVBoxLayout(wrap_group)
        
        # 自动换行复选框
        self.wrap_check = QCheckBox("自动换行")
        self.wrap_check.setChecked(True)
        wrap_layout.addWidget(self.wrap_check)
        
        general_layout.addWidget(wrap_group)

        recursive_group = QGroupBox("递归解密")
        recursive_layout = QVBoxLayout(recursive_group)

        depth_layout = QHBoxLayout()
        depth_layout.addWidget(QLabel("最大递归轮数:"))
        self.recursive_depth_spin = QSpinBox()
        self.recursive_depth_spin.setRange(1, 50)
        self.recursive_depth_spin.setValue(int(getattr(self.crypto_panel, 'recursive_max_depth', 10)))
        depth_layout.addWidget(self.recursive_depth_spin)
        depth_layout.addStretch()
        recursive_layout.addLayout(depth_layout)

        worker_layout = QHBoxLayout()
        worker_layout.addWidget(QLabel("并发线程数:"))
        self.recursive_workers_spin = QSpinBox()
        self.recursive_workers_spin.setRange(1, 32)
        self.recursive_workers_spin.setValue(int(getattr(self.crypto_panel, 'recursive_max_workers', 4)))
        worker_layout.addWidget(self.recursive_workers_spin)
        worker_layout.addStretch()
        recursive_layout.addLayout(worker_layout)

        tasks_layout = QHBoxLayout()
        tasks_layout.addWidget(QLabel("最大任务数:"))
        self.recursive_tasks_spin = QSpinBox()
        self.recursive_tasks_spin.setRange(50, 100000)
        self.recursive_tasks_spin.setValue(int(getattr(self.crypto_panel, 'recursive_max_tasks', 1000)))
        tasks_layout.addWidget(self.recursive_tasks_spin)
        tasks_layout.addStretch()
        recursive_layout.addLayout(tasks_layout)

        display_layout = QHBoxLayout()
        display_layout.addWidget(QLabel("最大显示结果数:"))
        self.recursive_display_spin = QSpinBox()
        self.recursive_display_spin.setRange(1, 1000)
        self.recursive_display_spin.setValue(int(getattr(self.crypto_panel, 'recursive_max_display_results', 100)))
        display_layout.addWidget(self.recursive_display_spin)
        display_layout.addWidget(QLabel("(上限 1000)"))
        display_layout.addStretch()
        recursive_layout.addLayout(display_layout)

        self.recursive_bruteforce_check = QCheckBox("对小密钥空间算法使用爆破结果（如凯撒）")
        self.recursive_bruteforce_check.setChecked(bool(getattr(self.crypto_panel, 'recursive_bruteforce', True)))
        recursive_layout.addWidget(self.recursive_bruteforce_check)

        recursive_layout.addWidget(QLabel("禁用内置特征（每行一个，留空表示全部启用）:"))
        self.recursive_disabled_features_edit = QTextEdit()
        self.recursive_disabled_features_edit.setPlaceholderText(
            "可禁用：flag格式、花括号文本、关键词、URL、JWT、JSON、XML/HTML、PEM、Hex候选、Base64候选、URL编码候选、高可读文本、英文词汇、低熵可读"
        )
        self.recursive_disabled_features_edit.setFixedHeight(70)
        disabled_features = getattr(self.crypto_panel, 'recursive_disabled_builtin_features', [])
        if not isinstance(disabled_features, list):
            disabled_features = []
        self.recursive_disabled_features_edit.setPlainText("\n".join(str(item) for item in disabled_features))
        recursive_layout.addWidget(self.recursive_disabled_features_edit)

        recursive_layout.addWidget(QLabel("自定义结果特征（每行：特征名=正则表达式）:"))
        self.recursive_custom_features_edit = QTextEdit()
        self.recursive_custom_features_edit.setPlaceholderText("例如：\n手机号=1[3-9][0-9]{9}\n邮箱=[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+")
        self.recursive_custom_features_edit.setFixedHeight(90)
        custom_features = normalize_custom_features(getattr(self.crypto_panel, 'recursive_custom_features', []))
        self.recursive_custom_features_edit.setPlainText("\n".join(
            f"{item['name']}={item['pattern']}" for item in custom_features
        ))
        recursive_layout.addWidget(self.recursive_custom_features_edit)

        general_layout.addWidget(recursive_group)
        general_layout.addStretch()           # 添加弹性空间，将内容推向上方
        tabs.addTab(general_tab, "常规")
        
    def _setup_font_tab(self, tabs: QTabWidget):
        """
        设置字体选项卡
        
        包含字体选择和大小调整功能：
        - 字体选择：打开系统字体对话框
        - 字体大小：通过数字调节器调整
        
        参数:
            tabs: 选项卡容器
        """
        font_tab = QWidget()
        font_layout = QVBoxLayout(font_tab)
        
        # ==================== 字体设置分组 ====================
        font_group = QGroupBox("字体设置")
        font_inner_layout = QVBoxLayout(font_group)
        
        # 字体选择行：显示当前字体 + 选择按钮
        font_btn_layout = QHBoxLayout()
        self.font_label = QLabel()
        current_font = self.crypto_panel.input_text.font()  # 获取当前字体
        self.font_label.setText(f"当前: {current_font.family()}, {current_font.pointSize()}pt")
        font_btn_layout.addWidget(self.font_label)
        
        self.font_btn = QPushButton("选择字体...")
        self.font_btn.clicked.connect(self.choose_font)       # 点击打开字体对话框
        font_btn_layout.addWidget(self.font_btn)
        font_btn_layout.addStretch()
        font_inner_layout.addLayout(font_btn_layout)
        
        # 字体大小行：标签 + 数字调节器
        size_layout = QHBoxLayout()
        size_layout.addWidget(QLabel("字体大小:"))
        self.font_size_spin = QSpinBox()
        self.font_size_spin.setRange(6, 32)                   # 字体大小范围6-32
        self.font_size_spin.setValue(current_font.pointSize())
        self.font_size_spin.valueChanged.connect(self.on_font_size_changed)
        size_layout.addWidget(self.font_size_spin)
        size_layout.addStretch()
        font_inner_layout.addLayout(size_layout)
        
        font_layout.addWidget(font_group)
        font_layout.addStretch()
        tabs.addTab(font_tab, "字体")
        
    def _setup_color_tab(self, tabs: QTabWidget):
        """
        设置颜色选项卡
        
        包含界面各元素的颜色自定义：
        - 按钮颜色：一键解密按钮颜色
        - 文本框颜色：输入框、输出框背景色
        - 界面颜色：菜单栏、状态栏、参数面板背景色
        
        使用滚动区域以支持更多颜色选项。
        
        参数:
            tabs: 选项卡容器
        """
        color_tab = QWidget()
        color_layout = QVBoxLayout(color_tab)
        
        # 创建滚动区域，支持内容过多时滚动
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)    # 自动调整内容大小
        scroll_area.setFrameShape(QFrame.NoFrame)  # 无边框
        
        # 滚动区域的内容容器
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setSpacing(10)
        
        # 添加各颜色设置分组
        self._setup_textbox_colors(scroll_layout)
        self._setup_ui_colors(scroll_layout)
        
        # 恢复默认颜色按钮
        reset_color_layout = QHBoxLayout()
        reset_color_btn = QPushButton("恢复默认颜色")
        reset_color_btn.clicked.connect(self.reset_colors)
        reset_color_layout.addStretch()
        reset_color_layout.addWidget(reset_color_btn)
        scroll_layout.addLayout(reset_color_layout)
        
        scroll_layout.addStretch()
        scroll_area.setWidget(scroll_content)
        color_layout.addWidget(scroll_area)
        tabs.addTab(color_tab, "颜色")
    
    def _setup_textbox_colors(self, layout: QVBoxLayout):
        """
        设置文本框颜色分组
        
        创建文本框颜色设置区域，包含：
        - 输入框背景颜色
        - 输出框背景颜色
        
        参数:
            layout: 要添加到的父布局
        """
        text_color_group = QGroupBox("文本框颜色")
        text_color_layout = QVBoxLayout(text_color_group)
        
        # 输入框背景颜色
        input_bg_layout = QHBoxLayout()
        input_bg_layout.addWidget(QLabel("输入框背景:"))
        self.input_bg_btn = QPushButton()
        self.input_bg_btn.setFixedSize(60, 25)
        self.input_bg_color = getattr(self.crypto_panel, 'input_bg_color', '#FFFFFF')
        self.input_bg_btn.setStyleSheet(f"background-color: {self.input_bg_color}; border: 1px solid #ccc;")
        self.input_bg_btn.clicked.connect(lambda: self.choose_color('input_bg'))
        input_bg_layout.addWidget(self.input_bg_btn)
        input_bg_layout.addStretch()
        text_color_layout.addLayout(input_bg_layout)
        
        # 输出框背景颜色
        output_bg_layout = QHBoxLayout()
        output_bg_layout.addWidget(QLabel("输出框背景:"))
        self.output_bg_btn = QPushButton()
        self.output_bg_btn.setFixedSize(60, 25)
        self.output_bg_color = getattr(self.crypto_panel, 'output_bg_color', '#F5F5F5')
        self.output_bg_btn.setStyleSheet(f"background-color: {self.output_bg_color}; border: 1px solid #ccc;")
        self.output_bg_btn.clicked.connect(lambda: self.choose_color('output_bg'))
        output_bg_layout.addWidget(self.output_bg_btn)
        output_bg_layout.addStretch()
        text_color_layout.addLayout(output_bg_layout)
        
        layout.addWidget(text_color_group)
        
    def _setup_ui_colors(self, layout: QVBoxLayout):
        """
        设置界面颜色分组
        
        创建界面颜色设置区域，包含：
        - 菜单栏背景颜色
        - 菜单栏文字颜色
        - 状态栏背景颜色
        - 参数面板背景颜色
        
        参数:
            layout: 要添加到的父布局
        """
        ui_color_group = QGroupBox("界面颜色")
        ui_color_layout = QVBoxLayout(ui_color_group)
        
        # 定义颜色设置项：(键名, 标签文本, 父窗口属性名, 按钮属性名)
        color_items = [
            ('menu_bg', '菜单栏背景:', 'menu_bg_color', 'menu_bg_btn'),
            ('menu_text', '菜单栏文字:', 'menu_text_color', 'menu_text_btn'),
            ('status_bg', '状态栏背景:', 'status_bg_color', 'status_bg_btn'),
            ('param_bg', '参数面板背景:', 'param_bg_color', 'param_bg_btn'),
        ]
        
        # 循环创建各颜色设置行
        for key, label_text, color_attr, btn_attr in color_items:
            h_layout = QHBoxLayout()
            h_layout.addWidget(QLabel(label_text))
            
            btn = QPushButton()
            btn.setFixedSize(60, 25)
            # 从父窗口读取当前颜色值
            color_value = getattr(self.parent_window, color_attr, getattr(self.crypto_panel, color_attr, '#FFFFFF'))
            setattr(self, color_attr, color_value)  # 保存到对话框实例
            btn.setStyleSheet(f"background-color: {color_value}; border: 1px solid #ccc;")
            # 绑定点击事件，lambda捕获key变量
            btn.clicked.connect(lambda checked, k=key: self.choose_color(k))
            setattr(self, btn_attr, btn)  # 保存按钮引用
            h_layout.addWidget(btn)
            h_layout.addStretch()
            ui_color_layout.addLayout(h_layout)
            
        layout.addWidget(ui_color_group)
        
    def _setup_sagemath_tab(self, tabs: QTabWidget):
        """
        设置SageMath选项卡
        
        包含SageMath解释器路径配置：
        - 类型选择：本机、WSL或网页端
        - 本机路径配置
        - WSL路径配置
        
        参数:
            tabs: 选项卡容器
        """
        sage_tab = QWidget()
        sage_layout = QVBoxLayout(sage_tab)
        
        type_group = QGroupBox("SageMath类型")
        type_layout = QVBoxLayout(type_group)
        
        self.sage_type_group = QButtonGroup(self)
        
        self.local_radio = QRadioButton("本机安装")
        self.wsl_radio = QRadioButton("WSL (Windows Subsystem for Linux)")
        self.online_radio = QRadioButton("网页端 SageCell")
        
        self.sage_type_group.addButton(self.local_radio, 0)
        self.sage_type_group.addButton(self.wsl_radio, 1)
        self.sage_type_group.addButton(self.online_radio, 2)
        
        self.local_radio.toggled.connect(self._on_sage_type_changed)
        self.wsl_radio.toggled.connect(self._on_sage_type_changed)
        
        type_layout.addWidget(self.local_radio)
        type_layout.addWidget(self.wsl_radio)
        type_layout.addWidget(self.online_radio)
        sage_layout.addWidget(type_group)
        
        local_group = QGroupBox("本机SageMath路径")
        local_layout = QVBoxLayout(local_group)
        
        local_path_layout = QHBoxLayout()
        self.local_path_edit = QLineEdit()
        self.local_path_edit.setPlaceholderText("选择sage可执行文件路径...")
        self.local_path_edit.setText(sage_config.get_local_path())
        local_path_layout.addWidget(self.local_path_edit)
        
        local_browse_btn = QPushButton("浏览...")
        local_browse_btn.clicked.connect(self._browse_local_path)
        local_path_layout.addWidget(local_browse_btn)
        local_layout.addLayout(local_path_layout)
        
        auto_detect_btn = QPushButton("自动检测")
        auto_detect_btn.clicked.connect(self._auto_detect_sage)
        local_layout.addWidget(auto_detect_btn)
        
        self.local_group = local_group
        sage_layout.addWidget(local_group)
        
        wsl_group = QGroupBox("WSL SageMath路径")
        wsl_layout = QVBoxLayout(wsl_group)
        
        distro_layout = QHBoxLayout()
        distro_layout.addWidget(QLabel("WSL发行版:"))
        self.wsl_distro_combo = QComboBox()
        self.wsl_distro_combo.setEditable(True)
        self.wsl_distro_combo.addItem("Ubuntu")
        self.wsl_distro_combo.addItem("Debian")
        self.wsl_distro_combo.addItem("kali-linux")
        self.wsl_distro_combo.setCurrentText(sage_config.get_wsl_distro())
        distro_layout.addWidget(self.wsl_distro_combo)
        distro_layout.addStretch()
        wsl_layout.addLayout(distro_layout)
        
        wsl_path_layout = QHBoxLayout()
        wsl_path_layout.addWidget(QLabel("Sage路径:"))
        self.wsl_path_edit = QLineEdit()
        self.wsl_path_edit.setPlaceholderText("/usr/bin/sage")
        self.wsl_path_edit.setText(sage_config.get_wsl_path())
        wsl_path_layout.addWidget(self.wsl_path_edit)
        wsl_layout.addLayout(wsl_path_layout)
        
        self.wsl_group = wsl_group
        sage_layout.addWidget(wsl_group)

        online_group = QGroupBox("网页端SageCell")
        online_layout = QVBoxLayout(online_group)

        online_url_layout = QHBoxLayout()
        online_url_layout.addWidget(QLabel("运行地址:"))
        self.online_url_edit = QLineEdit()
        self.online_url_edit.setPlaceholderText("https://sagecell.sagemath.org/")
        self.online_url_edit.setText(sage_config.get_online_url())
        online_url_layout.addWidget(self.online_url_edit)
        online_layout.addLayout(online_url_layout)

        self.online_group = online_group
        sage_layout.addWidget(online_group)
        
        status_group = QGroupBox("状态")
        status_layout = QVBoxLayout(status_group)
        
        self.sage_status_label = QLabel()
        self._update_sage_status()
        status_layout.addWidget(self.sage_status_label)
        
        test_btn = QPushButton("测试连接")
        test_btn.clicked.connect(self._test_sage_connection)
        status_layout.addWidget(test_btn)
        
        sage_layout.addWidget(status_group)
        sage_layout.addStretch()
        
        current_type = sage_config.get_sage_type()
        if current_type == 'local':
            self.local_radio.setChecked(True)
        elif current_type == 'online':
            self.online_radio.setChecked(True)
        else:
            self.wsl_radio.setChecked(True)
        
        self._on_sage_type_changed()
        
        tabs.addTab(sage_tab, "SageMath")

    def _setup_ai_tab(self, tabs: QTabWidget):
        ai_tab = QWidget()
        layout = QVBoxLayout(ai_tab)
        layout.setSpacing(12)

        self.ai_config = AIConfig()

        provider_group = QGroupBox("服务提供商")
        provider_group.setStyleSheet("""
            QGroupBox { font-weight: bold; font-size: 11pt; border: 1px solid #D0D0D0; border-radius: 6px; margin-top: 10px; padding-top: 15px; }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }
        """)
        provider_layout = QVBoxLayout()
        provider_layout.setSpacing(8)

        provider_label = QLabel("提供商")
        self.ai_provider_combo = QComboBox()
        self.ai_provider_combo.setMinimumHeight(30)
        providers = self.ai_config.get('providers', {})
        for key, info in providers.items():
            self.ai_provider_combo.addItem(info.get('name', key), key)
        current_provider = self.ai_config.get('provider', 'openai')
        for i in range(self.ai_provider_combo.count()):
            if self.ai_provider_combo.itemData(i) == current_provider:
                self.ai_provider_combo.setCurrentIndex(i)
                break
        self.ai_provider_combo.currentIndexChanged.connect(self._on_ai_provider_changed)
        provider_layout.addWidget(provider_label)
        provider_layout.addWidget(self.ai_provider_combo)

        api_key_label = QLabel("API密钥")
        self.ai_api_key_edit = QLineEdit()
        self.ai_api_key_edit.setEchoMode(QLineEdit.Password)
        self.ai_api_key_edit.setText(self.ai_config.get('api_key', ''))
        self.ai_api_key_edit.setPlaceholderText("输入API密钥")
        self.ai_api_key_edit.setMinimumHeight(30)
        provider_layout.addWidget(api_key_label)
        provider_layout.addWidget(self.ai_api_key_edit)

        api_base_label = QLabel("API地址 (可选)")
        self.ai_api_base_edit = QLineEdit()
        self.ai_api_base_edit.setText(self.ai_config.get('api_base', ''))
        self.ai_api_base_edit.setPlaceholderText("留空使用默认地址")
        self.ai_api_base_edit.setMinimumHeight(30)
        provider_layout.addWidget(api_base_label)
        provider_layout.addWidget(self.ai_api_base_edit)

        provider_group.setLayout(provider_layout)
        layout.addWidget(provider_group)

        model_group = QGroupBox("模型设置")
        model_group.setStyleSheet(provider_group.styleSheet())
        model_layout = QVBoxLayout()
        model_layout.setSpacing(8)

        model_label = QLabel("模型")
        model_row = QHBoxLayout()
        model_row.setSpacing(8)
        self.ai_model_combo = QComboBox()
        self.ai_model_combo.setEditable(True)
        self.ai_model_combo.setMinimumHeight(30)
        current_model = self.ai_config.get('model', '')
        self.ai_model_combo.lineEdit().setPlaceholderText("点击刷新获取模型，或手动输入")
        if current_model:
            self.ai_model_combo.setCurrentText(current_model)
        model_row.addWidget(self.ai_model_combo, stretch=1)

        self.ai_refresh_btn = QPushButton("刷新")
        self.ai_refresh_btn.setMinimumHeight(30)
        self.ai_refresh_btn.clicked.connect(self._ai_refresh_models)
        model_row.addWidget(self.ai_refresh_btn)

        model_layout.addWidget(model_label)
        model_layout.addLayout(model_row)

        model_group.setLayout(model_layout)
        layout.addWidget(model_group)

        temp_group = QGroupBox("高级参数")
        temp_group.setStyleSheet(provider_group.styleSheet())
        temp_layout = QVBoxLayout()
        temp_layout.setSpacing(8)
        temp_row = QHBoxLayout()
        temp_row.addWidget(QLabel("温度"))
        self.ai_temp_spin = QDoubleSpinBox()
        self.ai_temp_spin.setRange(0, 2)
        self.ai_temp_spin.setSingleStep(0.1)
        self.ai_temp_spin.setValue(self.ai_config.get('temperature', 0.7))
        temp_row.addWidget(self.ai_temp_spin)
        temp_row.addStretch()
        temp_row.addWidget(QLabel("最大Token"))
        self.ai_max_tokens_spin = QSpinBox()
        self.ai_max_tokens_spin.setRange(64, 32768)
        self.ai_max_tokens_spin.setSingleStep(256)
        self.ai_max_tokens_spin.setValue(self.ai_config.get('max_tokens', 2048))
        temp_row.addWidget(self.ai_max_tokens_spin)
        temp_layout.addLayout(temp_row)

        test_row = QHBoxLayout()
        self.ai_test_btn = QPushButton("测试连接")
        self.ai_test_btn.setMinimumHeight(32)
        self.ai_test_btn.clicked.connect(self._ai_test_connection)
        test_row.addStretch()
        test_row.addWidget(self.ai_test_btn)
        temp_layout.addLayout(test_row)

        temp_group.setLayout(temp_layout)
        layout.addWidget(temp_group)

        layout.addStretch()
        tabs.addTab(ai_tab, "AI配置")

        self._update_ollama_state()
        QTimer.singleShot(0, self._ai_refresh_models)

    def _update_ollama_state(self):
        provider = self.ai_provider_combo.currentData()
        if provider == 'ollama':
            self.ai_api_key_edit.setPlaceholderText("本地模型无需密钥")
            self.ai_api_key_edit.setEnabled(False)
        else:
            self.ai_api_key_edit.setPlaceholderText("输入API密钥")
            self.ai_api_key_edit.setEnabled(True)

    def _on_ai_provider_changed(self, index):
        provider = self.ai_provider_combo.currentData()
        provider_config = self.ai_config.get_provider_config(provider)

        old_provider = self.ai_config.get('provider', '')
        old_api_key = self.ai_api_key_edit.text()
        if old_api_key and old_provider != provider:
            providers = dict(self.ai_config.get('providers', {}))
            if old_provider in providers:
                providers[old_provider] = dict(providers[old_provider])
                providers[old_provider]['api_key'] = old_api_key
                self.ai_config.config['providers'] = providers
                self.ai_config.config['provider'] = provider

        self.ai_api_base_edit.setText(provider_config.get('api_base', ''))
        self._update_ollama_state()
        if provider != 'ollama':
            provider_api_key = provider_config.get('api_key', '')
            self.ai_api_key_edit.setText(provider_api_key)
        else:
            self.ai_api_key_edit.clear()
        self.ai_model_combo.clear()
        self.ai_model_combo.lineEdit().setPlaceholderText("点击刷新获取模型，或手动输入")
        self._ai_refresh_models()

    def _ai_refresh_models(self):
        provider = self.ai_provider_combo.currentData()
        api_base = self.ai_api_base_edit.text().strip()
        api_key = self.ai_api_key_edit.text().strip()

        if not api_key:
            api_key = self.ai_config.get('api_key', '')
        if not api_base:
            provider_config = self.ai_config.get_provider_config(provider)
            api_base = provider_config.get('api_base', '')
        if not api_base or (not api_key and provider != 'ollama'):
            return

        current = self.ai_model_combo.currentText()
        self.ai_refresh_btn.setEnabled(False)
        self.ai_refresh_btn.setText("加载中")
        self.ai_model_combo.clear()
        self.ai_model_combo.addItem("正在获取模型列表...")
        if current:
            self.ai_model_combo.setCurrentText(current)

        worker = ModelFetchWorker(provider, api_base, api_key)
        worker.models_ready.connect(self._on_ai_models_ready)
        worker.error_occurred.connect(lambda _: None)
        worker.finished.connect(lambda: (self.ai_refresh_btn.setEnabled(True), self.ai_refresh_btn.setText("刷新")))
        worker.start()
        self._ai_worker = worker

    def _on_ai_models_ready(self, models):
        current = self.ai_model_combo.currentText()
        if current == "正在获取模型列表...":
            current = self.ai_config.get('model', '')
        self.ai_model_combo.clear()
        if models:
            self.ai_model_combo.addItems(sorted(dict.fromkeys(models)))
        if current:
            self.ai_model_combo.setCurrentText(current)
        else:
            self.ai_model_combo.lineEdit().setPlaceholderText("点击刷新获取模型，或手动输入模型名")

    def _ai_test_connection(self):
        if not self._ai_save_config(require_complete=True):
            return
        client = AIClient(self.ai_config)
        success, message = client.test_connection()
        if success:
            QMessageBox.information(self, "成功", f"连接成功！\n{message}")
        else:
            QMessageBox.warning(self, "失败", message)

    def _ai_save_config(self, require_complete: bool = False):
        api_key = self.ai_api_key_edit.text().strip()
        model = self.ai_model_combo.currentText().strip()
        if require_complete and not api_key and self.ai_provider_combo.currentData() != 'ollama':
            QMessageBox.warning(self, "提示", "请输入API密钥")
            return False
        if require_complete and not model:
            QMessageBox.warning(self, "提示", "请选择或输入模型名称")
            return False
        self.ai_config.set('provider', self.ai_provider_combo.currentData())
        self.ai_config.set('api_key', api_key)
        self.ai_config.set('api_base', self.ai_api_base_edit.text().strip())
        self.ai_config.set('model', model)
        self.ai_config.set('temperature', self.ai_temp_spin.value())
        self.ai_config.set('max_tokens', self.ai_max_tokens_spin.value())
        self._reload_ai_panel()
        return True

    def _reload_ai_panel(self):
        ai_panel = getattr(self.parent_window, 'ai_panel', None)
        if ai_panel and hasattr(ai_panel, 'reload_config'):
            ai_panel.reload_config()

    def _setup_agent_tab(self, tabs: QTabWidget):
        agent_tab = QWidget()
        agent_layout = QVBoxLayout(agent_tab)

        mode_group = QGroupBox("权限模式")
        mode_layout = QVBoxLayout(mode_group)
        self.agent_permission_mode_combo = QComboBox()
        self.agent_permission_mode_combo.addItem("可执行安全命令：允许白名单命令，删除/破坏性命令禁用", "command")
        self.agent_permission_mode_combo.addItem("只读：仅允许读操作（已废弃）", "readonly")
        self.agent_permission_mode_combo.addItem("可写：允许写文件（已废弃）", "writable")
        mode_index = self.agent_permission_mode_combo.findData(self.agent_config.permission_mode)
        self.agent_permission_mode_combo.setCurrentIndex(mode_index if mode_index >= 0 else 0)
        mode_layout.addWidget(self.agent_permission_mode_combo)
        mode_layout.addWidget(QLabel("固定安全边界：不能删除文件，不能执行 rm/del/format/kill/reset 等破坏性命令，不能访问敏感配置。"))
        agent_layout.addWidget(mode_group)

        confirm_group = QGroupBox("确认策略")
        confirm_layout = QVBoxLayout(confirm_group)
        self.agent_confirm_command_check = QCheckBox("执行命令每次都需要用户确认")
        self.agent_confirm_command_check.setChecked(bool(self.agent_config.get("require_confirmation_for_command")))
        confirm_layout.addWidget(self.agent_confirm_command_check)
        agent_layout.addWidget(confirm_group)

        tools_group = QGroupBox("允许的工具")
        tools_layout = QVBoxLayout(tools_group)
        self.agent_command_tool_check = QCheckBox("执行白名单命令 run_command")
        self.agent_command_tool_check.setChecked("run_command" in self.agent_config.get("enabled_command_tools", []))
        tools_layout.addWidget(self.agent_command_tool_check)
        tools_layout.addWidget(QLabel("所有操作（列目录、读文件、搜索文本、写文件等）都通过命令进行。"))
        tools_layout.addWidget(QLabel("固定禁用：delete_file，以及包含 rm/del/remove/format/kill/reset/clean 等关键字的命令。"))
        agent_layout.addWidget(tools_group)

        commands_group = QGroupBox("命令白名单")
        commands_layout = QVBoxLayout(commands_group)
        self.agent_allowed_commands_edit = QLineEdit()
        self.agent_allowed_commands_edit.setText("; ".join(self.agent_config.get("allowed_commands", [])))
        self.agent_allowed_commands_edit.setPlaceholderText("用分号分隔；* 表示允许所有非破坏性命令")
        commands_layout.addWidget(QLabel("仅 command 模式下可执行；* 允许所有非破坏性命令，仍会过滤 rm/del/kill/reset/clean 等危险命令。"))
        commands_layout.addWidget(self.agent_allowed_commands_edit)
        agent_layout.addWidget(commands_group)

        agent_layout.addStretch()
        tabs.addTab(agent_tab, "Agent")
    
    def _setup_algorithm_tabs_tab(self, tabs: QTabWidget):
        algo_tab = QWidget()
        layout = QVBoxLayout(algo_tab)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setSpacing(10)

        intro = QLabel("勾选的算法将作为选项卡显示在主界面中，方便快速访问。\n菜单栏中的入口不受影响，始终可用。")
        intro.setStyleSheet("color:#888; font-size:9pt; padding:4px;")
        intro.setWordWrap(True)
        scroll_layout.addWidget(intro)

        self.algo_tab_checkboxes = {}
        enabled = self.parent_window.app_config.get("enabled_algorithm_tabs", {})

        asym_group = QGroupBox("非对称密码算法")
        asym_layout = QVBoxLayout(asym_group)
        asym_layout.setSpacing(6)
        for defn in self.algorithm_tab_defs:
            if defn.get("category") != "非对称密码":
                continue
            name = defn["name"]
            desc = defn.get("desc", "")
            cb = QCheckBox(f"{name} — {desc}")
            cb.setChecked(enabled.get(name, bool(defn.get("enabled", True))))
            self.algo_tab_checkboxes[name] = cb
            asym_layout.addWidget(cb)
        scroll_layout.addWidget(asym_group)

        sym_group = QGroupBox("对称密码算法")
        sym_layout = QVBoxLayout(sym_group)
        sym_layout.setSpacing(6)
        for defn in self.algorithm_tab_defs:
            if defn.get("category") != "对称密码":
                continue
            name = defn["name"]
            desc = defn.get("desc", "")
            cb = QCheckBox(f"{name} — {desc}")
            cb.setChecked(enabled.get(name, bool(defn.get("enabled", True))))
            self.algo_tab_checkboxes[name] = cb
            sym_layout.addWidget(cb)
        scroll_layout.addWidget(sym_group)

        scroll_layout.addStretch()
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)
        tabs.addTab(algo_tab, "算法选项卡")
    
    def _on_sage_type_changed(self):
        """SageMath类型改变时的处理"""
        is_local = self.local_radio.isChecked()
        is_wsl = self.wsl_radio.isChecked()
        is_online = self.online_radio.isChecked()
        self.local_group.setEnabled(is_local)
        self.wsl_group.setEnabled(is_wsl)
        self.online_group.setEnabled(is_online)
    
    def _browse_local_path(self):
        """浏览选择本机SageMath路径"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "选择SageMath可执行文件",
            "",
            "可执行文件 (*.exe);;所有文件 (*)"
        )
        if file_path:
            self.local_path_edit.setText(file_path)
    
    def _auto_detect_sage(self):
        """自动检测本机SageMath安装"""
        detected = sage_config.detect_local_installations()
        
        if detected:
            detected_paths = '\n'.join(detected[:5])
            if len(detected) > 5:
                detected_paths += f"\n... 共检测到 {len(detected)} 个"
            
            reply = QMessageBox.question(
                self,
                "检测到SageMath",
                f"检测到以下SageMath安装:\n{detected_paths}\n\n是否使用第一个?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes
            )
            
            if reply == QMessageBox.Yes:
                self.local_path_edit.setText(detected[0])
        else:
            QMessageBox.information(
                self,
                "未检测到SageMath",
                "未能自动检测到SageMath安装，请手动配置路径。"
            )
    
    def _test_sage_connection(self):
        """测试SageMath连接"""
        import subprocess
        
        if self.local_radio.isChecked():
            path = self.local_path_edit.text().strip()
            if not path:
                QMessageBox.warning(self, "错误", "请先配置本机SageMath路径")
                return
            
            try:
                result = subprocess.run(
                    [path, '--version'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    version_info = result.stdout.strip().split('\n')[0] if result.stdout else "SageMath"
                    QMessageBox.information(self, "成功", f"连接成功!\n{version_info}")
                else:
                    QMessageBox.warning(self, "失败", f"执行失败:\n{result.stderr}")
            except FileNotFoundError:
                QMessageBox.warning(self, "失败", f"找不到文件: {path}")
            except subprocess.TimeoutExpired:
                QMessageBox.warning(self, "失败", "执行超时")
            except Exception as e:
                QMessageBox.warning(self, "失败", f"执行出错:\n{str(e)}")
        elif self.wsl_radio.isChecked():
            distro = self.wsl_distro_combo.currentText().strip()
            wsl_path = self.wsl_path_edit.text().strip()
            
            if not distro or not wsl_path:
                QMessageBox.warning(self, "错误", "请先配置WSL发行版和Sage路径")
                return
            
            try:
                cmd = ['wsl', '-d', distro, wsl_path, '--version']
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                if result.returncode == 0:
                    version_info = result.stdout.strip().split('\n')[0] if result.stdout else "SageMath"
                    QMessageBox.information(self, "成功", f"WSL连接成功!\n{version_info}")
                else:
                    QMessageBox.warning(self, "失败", f"执行失败:\n{result.stderr}")
            except subprocess.TimeoutExpired:
                QMessageBox.warning(self, "失败", "执行超时")
            except Exception as e:
                QMessageBox.warning(self, "失败", f"执行出错:\n{str(e)}")
        else:
            from core.sage_executor import SageExecutor

            original_type = sage_config.get_sage_type()
            original_url = sage_config.get_online_url()
            sage_config.set_sage_type('online')
            sage_config.set_online_url(self.online_url_edit.text().strip())

            try:
                success, output = SageExecutor().execute('print(2 + 3)', timeout=90)
                if success:
                    QMessageBox.information(self, "成功", "SageCell连接成功!")
                else:
                    QMessageBox.warning(self, "失败", output)
            finally:
                sage_config.set_sage_type(original_type)
                sage_config.set_online_url(original_url)
    
    def _update_sage_status(self):
        """更新SageMath状态显示"""
        if sage_config.is_configured():
            self.sage_status_label.setText("状态: 已配置 ✓")
            self.sage_status_label.setStyleSheet("color: green;")
        else:
            self.sage_status_label.setText("状态: 未配置 ✗")
            self.sage_status_label.setStyleSheet("color: red;")
        
    def _setup_buttons(self, layout: QVBoxLayout):
        """
        设置底部按钮
        
        创建确定、取消、应用三个按钮：
        - 确定：应用设置并关闭对话框
        - 取消：放弃更改并关闭对话框
        - 应用：应用设置但不关闭对话框
        
        参数:
            layout: 主布局
        """
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()  # 将按钮推到右侧
        
        # 确定按钮
        ok_btn = QPushButton("确定")
        ok_btn.setMinimumWidth(80)
        ok_btn.clicked.connect(self.accept)  # 调用accept方法
        btn_layout.addWidget(ok_btn)
        
        # 取消按钮
        cancel_btn = QPushButton("取消")
        cancel_btn.setMinimumWidth(80)
        cancel_btn.clicked.connect(self.reject)  # 调用reject方法关闭对话框
        btn_layout.addWidget(cancel_btn)
        
        # 应用按钮
        apply_btn = QPushButton("应用")
        apply_btn.setMinimumWidth(80)
        apply_btn.clicked.connect(self.apply_settings)  # 只应用设置，不关闭
        btn_layout.addWidget(apply_btn)
        
        layout.addLayout(btn_layout)
        
    def choose_font(self):
        """
        打开字体选择对话框
        
        使用系统字体对话框让用户选择字体，
        选择后更新字体标签显示和大小调节器。
        """
        font, ok = QFontDialog.getFont(
            self.crypto_panel.input_text.font(),  # 当前字体作为初始值
            self,
            "选择字体"
        )
        if ok:
            self.selected_font = font  # 保存选择的字体
            self.font_label.setText(f"当前: {font.family()}, {font.pointSize()}pt")
            self.font_size_spin.setValue(font.pointSize())  # 同步大小调节器
            
    def on_font_size_changed(self, size: int):
        """
        字体大小改变时的处理
        
        当用户通过数字调节器改变字体大小时，
        创建新的字体对象并更新显示。
        
        参数:
            size (int): 新的字体大小
        """
        font = self.crypto_panel.input_text.font()
        font.setPointSize(size)
        self.selected_font = font
        self.font_label.setText(f"当前: {font.family()}, {size}pt")
        
    def choose_color(self, target: str):
        """
        打开颜色选择对话框
        
        根据目标类型打开颜色选择对话框，
        选择后更新颜色预览按钮的样式。
        
        参数:
            target (str): 目标颜色类型
        """
        color_map = {
            'input_bg': ('input_bg_color', 'input_bg_btn'),
            'output_bg': ('output_bg_color', 'output_bg_btn'),
            'menu_bg': ('menu_bg_color', 'menu_bg_btn'),
            'menu_text': ('menu_text_color', 'menu_text_btn'),
            'status_bg': ('status_bg_color', 'status_bg_btn'),
            'param_bg': ('param_bg_color', 'param_bg_btn'),
        }
        
        if target not in color_map:
            return
            
        color_attr, btn_attr = color_map[target]
        current = QColor(getattr(self, color_attr))
        color = QColorDialog.getColor(current, self, "选择颜色")
        
        if color.isValid():
            hex_color = color.name()
            setattr(self, color_attr, hex_color)
            btn = getattr(self, btn_attr)
            btn.setStyleSheet(f"background-color: {hex_color}; border: 1px solid #ccc;")
            
    def reset_colors(self):
        """
        重置所有颜色为默认值
        """
        default_colors = {
            'input_bg_color': '#FFFFFF',
            'output_bg_color': '#FFFFFF',
            'menu_bg_color': '#F5F5F5',
            'menu_text_color': '#333333',
            'status_bg_color': '#F0F0F0',
            'param_bg_color': '#FAFAFA',
        }
        
        btn_map = {
            'input_bg_color': 'input_bg_btn',
            'output_bg_color': 'output_bg_btn',
            'menu_bg_color': 'menu_bg_btn',
            'menu_text_color': 'menu_text_btn',
            'status_bg_color': 'status_bg_btn',
            'param_bg_color': 'param_bg_btn',
        }
        
        for color_attr, default_color in default_colors.items():
            setattr(self, color_attr, default_color)
            btn_attr = btn_map[color_attr]
            btn = getattr(self, btn_attr)
            btn.setStyleSheet(f"background-color: {default_color}; border: 1px solid #ccc;")
            
    def apply_settings(self):
        """
        应用当前设置到主窗口
        
        将对话框中的所有设置应用到父窗口，
        包括常规选项、字体设置、颜色设置和SageMath配置。
        """
        # ==================== 应用常规设置 ====================
        self.crypto_panel.auto_copy = self.auto_copy_check.isChecked()
        self.crypto_panel.auto_swap = self.auto_swap_check.isChecked()
        self.crypto_panel.recursive_max_depth = self.recursive_depth_spin.value()
        self.crypto_panel.recursive_max_workers = self.recursive_workers_spin.value()
        self.crypto_panel.recursive_max_tasks = self.recursive_tasks_spin.value()
        self.crypto_panel.recursive_max_display_results = self.recursive_display_spin.value()
        self.crypto_panel.recursive_bruteforce = self.recursive_bruteforce_check.isChecked()
        self.crypto_panel.recursive_disabled_builtin_features = self._parse_disabled_builtin_features()
        self.crypto_panel.recursive_custom_features = self._parse_recursive_custom_features()
        self.crypto_panel.async_decryptor = None
        if hasattr(self.parent_window, 'auto_copy_action'):
            self.parent_window.auto_copy_action.setChecked(self.auto_copy_check.isChecked())
        if hasattr(self.parent_window, 'auto_swap_action'):
            self.parent_window.auto_swap_action.setChecked(self.auto_swap_check.isChecked())
            
        # ==================== 应用字体设置 ====================
        if hasattr(self, 'selected_font'):
            self.crypto_panel.input_text.setFont(self.selected_font)
            self.crypto_panel.output_text.setFont(self.selected_font)
            
        # ==================== 应用颜色设置 ====================
        self.crypto_panel.input_bg_color = self.input_bg_color
        self.crypto_panel.output_bg_color = self.output_bg_color
        self.parent_window.menu_bg_color = self.menu_bg_color
        self.parent_window.menu_text_color = self.menu_text_color
        self.parent_window.status_bg_color = self.status_bg_color
        self.crypto_panel.param_bg_color = self.param_bg_color
        
        # 调用主窗口的方法应用颜色到界面
        self.parent_window.apply_colors()
        if hasattr(self.crypto_panel, 'apply_colors'):
            self.crypto_panel.apply_colors()
        if hasattr(self.parent_window, 'save_settings'):
            self.parent_window.save_settings()
        
        # ==================== 应用SageMath设置 ====================
        if hasattr(self, 'local_radio'):
            if self.local_radio.isChecked():
                sage_type = 'local'
            elif self.wsl_radio.isChecked():
                sage_type = 'wsl'
            else:
                sage_type = 'online'
            sage_config.set_sage_type(sage_type)
            sage_config.set_local_path(self.local_path_edit.text().strip())
            sage_config.set_wsl_distro(self.wsl_distro_combo.currentText().strip())
            sage_config.set_wsl_path(self.wsl_path_edit.text().strip())
            sage_config.set_online_url(self.online_url_edit.text().strip())
            sage_config.save_config()
            self._update_sage_status()

        # ==================== 应用AI配置 ====================
        if hasattr(self, 'ai_provider_combo'):
            self._ai_save_config()

        # ==================== 应用Agent权限设置 ====================
        if hasattr(self, 'agent_permission_mode_combo'):
            allowed_commands = [
                command.strip()
                for command in self.agent_allowed_commands_edit.text().split(';')
                if command.strip()
            ]
            self.agent_config.update({
                "permission_mode": self.agent_permission_mode_combo.currentData(),
                "require_confirmation_for_command": self.agent_confirm_command_check.isChecked(),
                "enabled_command_tools": ["run_command"] if self.agent_command_tool_check.isChecked() else [],
                "allowed_commands": allowed_commands,
            })
            self._refresh_agent_panel_permission_config()

        # ==================== 应用算法选项卡设置 ====================
        if hasattr(self, 'algo_tab_checkboxes'):
            enabled_tabs = {}
            for name, cb in self.algo_tab_checkboxes.items():
                enabled_tabs[name] = cb.isChecked()
            self.parent_window.app_config["enabled_algorithm_tabs"] = enabled_tabs
            self.parent_window.refresh_algorithm_tabs()
            if hasattr(self.parent_window, 'save_settings'):
                self.parent_window.save_settings()

    def _refresh_agent_panel_permission_config(self):
        ai_panel = getattr(self.parent_window, 'ai_panel', None)
        agent_panel = getattr(ai_panel, 'agent_panel', None)
        if agent_panel and hasattr(agent_panel, 'reload_permission_config'):
            agent_panel.reload_permission_config()
        
    def accept(self):
        """
        确定按钮点击时的处理
        
        应用设置并关闭对话框。
        重写QDialog的accept方法。
        """
        self.apply_settings()
        super().accept()  # 调用父类方法关闭对话框

    def _parse_recursive_custom_features(self):
        features = []
        for line in self.recursive_custom_features_edit.toPlainText().splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' not in line:
                continue
            name, pattern = [part.strip() for part in line.split('=', 1)]
            if name and pattern:
                features.append({
                    "name": name,
                    "pattern": pattern,
                    "score": 25,
                    "ignore_case": True,
                    "strong": True,
                })
        return features

    def _parse_disabled_builtin_features(self):
        features = []
        for line in self.recursive_disabled_features_edit.toPlainText().splitlines():
            line = line.strip()
            if line and not line.startswith('#') and line not in features:
                features.append(line)
        return features
