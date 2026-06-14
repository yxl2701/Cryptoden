"""
AI配置对话框
===========
提供API配置界面，配置后自动保存
"""

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QComboBox, QDoubleSpinBox, QSpinBox,
    QGroupBox, QMessageBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer

from utils.ai_assistant import AIConfig, AIClient, get_available_models, AI_CONFIG_FILE

import json


class ModelFetchWorker(QThread):
    models_ready = pyqtSignal(list)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, provider, api_base, api_key):
        super().__init__()
        self.provider = provider
        self.api_base = api_base
        self.api_key = api_key
    
    def run(self):
        try:
            self.models_ready.emit(get_available_models(self.provider, self.api_base, self.api_key))
        except Exception as e:
            self.error_occurred.emit(str(e))


class AIConfigDialog(QDialog):
    """AI配置对话框 - 首次使用时必须配置"""
    
    def __init__(self, parent=None, require_config=False):
        super().__init__(parent)
        self.config = AIConfig()
        self.require_config = require_config
        self.model_worker = None
        self.setWindowTitle("AI配置")
        self.setMinimumSize(450, 400)
        self.setModal(True)
        self.setup_ui()
        
        if require_config:
            self.setWindowFlags(self.windowFlags() & ~Qt.WindowCloseButtonHint)
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        if self.require_config:
            hint = QLabel("⚠️ 使用AI功能前请先配置API")
            hint.setStyleSheet("color: #FF9800; font-size: 14pt; font-weight: bold;")
            hint.setAlignment(Qt.AlignCenter)
            layout.addWidget(hint)
        
        provider_group = QGroupBox("服务提供商")
        provider_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 11pt;
                border: 1px solid #D0D0D0;
                border-radius: 6px;
                margin-top: 10px;
                padding-top: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        provider_layout = QVBoxLayout()
        provider_layout.setSpacing(10)
        
        provider_label = QLabel("提供商")
        self.provider_combo = QComboBox()
        self.provider_combo.setMinimumHeight(32)
        providers = self.config.get('providers', {})
        for key, info in providers.items():
            self.provider_combo.addItem(info.get('name', key), key)
        
        current_provider = self.config.get('provider', 'openai')
        for i in range(self.provider_combo.count()):
            if self.provider_combo.itemData(i) == current_provider:
                self.provider_combo.setCurrentIndex(i)
                break
        
        self.provider_combo.currentIndexChanged.connect(self.on_provider_changed)
        provider_layout.addWidget(provider_label)
        provider_layout.addWidget(self.provider_combo)
        
        api_key_label = QLabel("API密钥")
        self.api_key_edit = QLineEdit()
        self.api_key_edit.setEchoMode(QLineEdit.Password)
        self.api_key_edit.setText(self.config.get('api_key', ''))
        self.api_key_edit.setPlaceholderText("输入API密钥")
        self.api_key_edit.setMinimumHeight(32)
        provider_layout.addWidget(api_key_label)
        provider_layout.addWidget(self.api_key_edit)
        
        api_base_label = QLabel("API地址 (可选)")
        self.api_base_edit = QLineEdit()
        self.api_base_edit.setText(self.config.get('api_base', ''))
        self.api_base_edit.setPlaceholderText("留空使用默认地址")
        self.api_base_edit.setMinimumHeight(32)
        provider_layout.addWidget(api_base_label)
        provider_layout.addWidget(self.api_base_edit)
        
        provider_group.setLayout(provider_layout)
        layout.addWidget(provider_group)
        
        model_group = QGroupBox("模型设置")
        model_group.setStyleSheet(provider_group.styleSheet())
        model_layout = QVBoxLayout()
        model_layout.setSpacing(10)
        
        model_label = QLabel("模型")
        model_row = QHBoxLayout()
        model_row.setSpacing(8)
        self.model_combo = QComboBox()
        self.model_combo.setEditable(True)
        self.model_combo.setMinimumHeight(32)
        self.update_model_list([])
        current_model = self.config.get('model', '')
        if current_model:
            self.model_combo.setCurrentText(current_model)
        model_row.addWidget(self.model_combo, stretch=1)
        
        self.refresh_models_btn = QPushButton("刷新")
        self.refresh_models_btn.setMinimumHeight(32)
        self.refresh_models_btn.clicked.connect(self.refresh_models)
        model_row.addWidget(self.refresh_models_btn)
        
        model_layout.addWidget(model_label)
        model_layout.addLayout(model_row)
        
        model_group.setLayout(model_layout)
        layout.addWidget(model_group)
        
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(15)
        
        if not self.require_config:
            cancel_btn = QPushButton("取消")
            cancel_btn.setMinimumHeight(40)
            cancel_btn.clicked.connect(self.reject)
            btn_layout.addWidget(cancel_btn)
        
        test_btn = QPushButton("测试连接")
        test_btn.setMinimumHeight(40)
        test_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                border: none;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #F57C00;
            }
        """)
        test_btn.clicked.connect(self.test_connection)
        btn_layout.addWidget(test_btn)
        
        save_btn = QPushButton("保存配置")
        save_btn.setMinimumHeight(40)
        save_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #388E3C;
            }
        """)
        save_btn.clicked.connect(self.save_and_accept)
        btn_layout.addWidget(save_btn)
        
        layout.addLayout(btn_layout)
        QTimer.singleShot(0, self.refresh_models)
    
    def update_model_list(self, models=None):
        current = self.model_combo.currentText()
        self.model_combo.clear()
        models = models or []
        if models:
            self.model_combo.addItems(sorted(dict.fromkeys(models)))
        if current:
            self.model_combo.setCurrentText(current)
        elif not models:
            self.model_combo.setEditText("")
            self.model_combo.lineEdit().setPlaceholderText("点击刷新获取模型，或手动输入模型名")
    
    def on_provider_changed(self, index):
        provider = self.provider_combo.currentData()
        provider_config = self.config.get_provider_config(provider)

        old_provider = self.config.get('provider', '')
        old_api_key = self.api_key_edit.text()
        if old_api_key and old_provider != provider:
            providers = dict(self.config.get('providers', {}))
            if old_provider in providers:
                providers[old_provider] = dict(providers[old_provider])
                providers[old_provider]['api_key'] = old_api_key
                self.config.config['providers'] = providers
                self.config.config['provider'] = provider

        default_base = provider_config.get('api_base', '')
        self.api_base_edit.setText(default_base)
        
        self.update_model_list([])
        
        if provider == 'ollama':
            self.api_key_edit.setPlaceholderText("本地模型无需密钥")
            self.api_key_edit.setEnabled(False)
            self.api_key_edit.clear()
        else:
            provider_api_key = provider_config.get('api_key', '')
            self.api_key_edit.setText(provider_api_key)
            self.api_key_edit.setPlaceholderText("输入API密钥")
            self.api_key_edit.setEnabled(True)
        
        self.refresh_models()
    
    def refresh_models(self):
        """异步获取在线模型列表；失败时保留当前模型并允许手动输入。"""
        provider = self.provider_combo.currentData()
        api_base = self.api_base_edit.text().strip()
        api_key = self.api_key_edit.text().strip()
        
        # 如果用户没填 key 但配置里有，用配置里的
        if not api_key:
            api_key = self.config.get('api_key', '')
        
        if not api_base:
            provider_config = self.config.get_provider_config(provider)
            api_base = provider_config.get('api_base', '')
        
        if not api_base or (not api_key and provider != 'ollama'):
            return
        
        if self.model_worker and self.model_worker.isRunning():
            return
        
        current = self.model_combo.currentText()
        self.refresh_models_btn.setEnabled(False)
        self.refresh_models_btn.setText("加载中")
        self.model_combo.clear()
        self.model_combo.addItem("正在获取模型列表...")
        if current:
            self.model_combo.setCurrentText(current)
        
        self.model_worker = ModelFetchWorker(provider, api_base, api_key)
        self.model_worker.models_ready.connect(self.on_models_ready)
        self.model_worker.error_occurred.connect(self.on_models_error)
        self.model_worker.finished.connect(self.on_models_finished)
        self.model_worker.start()
    
    def on_models_ready(self, models):
        current = self.model_combo.currentText()
        if current == "正在获取模型列表...":
            current = self.config.get('model', '')
        self.update_model_list(models)
        if current:
            self.model_combo.setCurrentText(current)
    
    def on_models_error(self, error_msg):
        self.update_model_list([])
    
    def on_models_finished(self):
        self.refresh_models_btn.setEnabled(True)
        self.refresh_models_btn.setText("刷新")
    
    def save_config(self):
        self.config.set('provider', self.provider_combo.currentData())
        self.config.set('api_key', self.api_key_edit.text())
        self.config.set('api_base', self.api_base_edit.text())
        self.config.set('model', self.model_combo.currentText())
    
    def save_and_accept(self):
        api_key = self.api_key_edit.text().strip()
        if not api_key and self.provider_combo.currentData() != 'ollama':
            QMessageBox.warning(self, "提示", "请输入API密钥")
            return
        
        model = self.model_combo.currentText().strip()
        if not model:
            QMessageBox.warning(self, "提示", "请选择或输入模型名称")
            return
        
        self.save_config()
        QMessageBox.information(self, "成功", "配置已保存！")
        self.accept()
    
    def test_connection(self):
        self.save_config()
        client = AIClient(self.config)
        
        success, message = client.test_connection()
        
        if success:
            QMessageBox.information(self, "成功", f"连接成功！\n{message}")
        else:
            QMessageBox.warning(self, "失败", message)
    
    @staticmethod
    def is_configured():
        """检查是否已配置"""
        try:
            cfg = AIConfig()
            api_key = cfg.get('api_key', '')
            provider = cfg.get('provider', '')
            return bool(api_key or provider == 'ollama')
        except Exception:
            return False
