"""
AI助手对话框
===========
提供AI对话界面，支持配置和对话
"""

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox,
    QGroupBox, QMessageBox, QWidget, QFrame, QApplication,
    QTextBrowser
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QUrl
from PyQt5.QtGui import QFont, QColor, QTextCursor, QTextDocument

import sys
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
root_str = str(project_root)
if root_str not in sys.path:
    sys.path.insert(0, root_str)
from utils.ai_assistant import AIConfig, AIClient, get_available_models
from .clipboard_utils import install_plain_text_copy
from .file_drop_helper import TextFileDropHelper

try:
    import markdown
    MARKDOWN_AVAILABLE = True
except ImportError:
    MARKDOWN_AVAILABLE = False


class ChatWorker(QThread):
    """聊天工作线程"""
    response_ready = pyqtSignal(str)
    error_occurred = pyqtSignal(str)
    finished_chat = pyqtSignal()
    
    def __init__(self, client, message, stream=True):
        super().__init__()
        self.client = client
        self.message = message
        self.stream = stream
    
    def run(self):
        try:
            for chunk in self.client.chat(self.message, self.stream):
                if chunk.startswith("错误") or chunk.startswith("API错误") or chunk.startswith("网络错误") or chunk.startswith("无法连接") or chunk.startswith("请求失败") or chunk.startswith("请求超时") or chunk.startswith("[错误:"):
                    self.error_occurred.emit(chunk)
                else:
                    self.response_ready.emit(chunk)
        except Exception as e:
            self.error_occurred.emit(str(e))
        finally:
            self.finished_chat.emit()


class ModelRefreshWorker(QThread):
    """模型刷新工作线程"""
    models_ready = pyqtSignal(list)
    
    def __init__(self, provider, api_base, api_key):
        super().__init__()
        self.provider = provider
        self.api_base = api_base
        self.api_key = api_key
    
    def run(self):
        try:
            models = get_available_models(self.provider, self.api_base, self.api_key)
            self.models_ready.emit(models)
        except Exception:
            self.models_ready.emit([])


class AIAssistantDialog(QDialog):
    """AI助手对话框"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.config = AIConfig()
        self.client = AIClient(self.config)
        self.worker = None
        self.model_worker = None
        self.input_drop_helper = None
        self.current_ai_content = ""
        
        self.setWindowTitle("AI助手")
        self.setMinimumSize(1100, 900)
        self.resize(1000, 750)
        self.setup_ui()
        install_plain_text_copy(self)
        self.input_drop_helper = TextFileDropHelper(self, self.input_edit)
    
    def setup_ui(self):
        main_layout = QHBoxLayout()
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(10, 10, 10, 10)
        
        left_panel = self._create_chat_panel()
        main_layout.addWidget(left_panel, stretch=3)
        
        right_panel = self._create_config_panel()
        main_layout.addWidget(right_panel, stretch=1)
        
        self.setLayout(main_layout)
    
    def _create_chat_panel(self):
        """创建聊天面板"""
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(12)
        layout.setContentsMargins(0, 0, 0, 0)
        
        header = QHBoxLayout()
        title = QLabel("💬 对话")
        title.setStyleSheet("font-size: 12pt; font-weight: bold; color: #333;")
        header.addWidget(title)
        header.addStretch()
        
        clear_btn = QPushButton("清空对话")
        clear_btn.setFixedHeight(32)
        clear_btn.setStyleSheet("font-size: 12pt;")
        clear_btn.clicked.connect(self.clear_chat)
        header.addWidget(clear_btn)
        layout.addLayout(header)
        
        self.chat_display = QTextBrowser()
        self.chat_display.setReadOnly(True)
        self.chat_display.setFont(QFont("Microsoft YaHei", 12))
        self.chat_display.setStyleSheet("""
            QTextBrowser {
                background-color: #FFFFFF;
                border: 1px solid #E0E0E0;
                border-radius: 8px;
                padding: 12px;
                font-size: 12pt;
            }
        """)
        self.chat_display.setMinimumHeight(400)
        self.chat_display.setOpenExternalLinks(True)
        layout.addWidget(self.chat_display, stretch=1)
        
        input_frame = QFrame()
        input_frame.setStyleSheet("""
            QFrame {
                background-color: #FAFAFA;
                border: 1px solid #E0E0E0;
                border-radius: 8px;
                padding: 8px;
            }
        """)
        input_layout = QVBoxLayout(input_frame)
        input_layout.setContentsMargins(12, 10, 12, 10)
        input_layout.setSpacing(10)
        
        input_header = QHBoxLayout()
        input_label = QLabel("📝 输入消息")
        input_label.setStyleSheet("font-weight: bold; color: #555; font-size: 12pt;")
        input_header.addWidget(input_label)
        input_header.addStretch()
        
        hint_label = QLabel("Enter发送 | Shift+Enter换行")
        hint_label.setStyleSheet("color: #999; font-size: 12pt;")
        input_header.addWidget(hint_label)
        input_layout.addLayout(input_header)
        
        input_row = QHBoxLayout()
        input_row.setSpacing(12)
        
        self.input_edit = QTextEdit()
        self.input_edit.setPlaceholderText("输入您的问题...")
        self.input_edit.setFont(QFont("Microsoft YaHei", 12))
        self.input_edit.setStyleSheet("""
            QTextEdit {
                background-color: #FFFFFF;
                border: 1px solid #DDD;
                border-radius: 6px;
                padding: 10px;
                font-size: 12pt;
            }
        """)
        self.input_edit.setMinimumHeight(80)
        self.input_edit.setMaximumHeight(140)
        self.input_edit.installEventFilter(self)
        input_row.addWidget(self.input_edit, stretch=1)
        
        btn_layout = QVBoxLayout()
        btn_layout.setSpacing(8)
        
        self.send_btn = QPushButton("发送")
        self.send_btn.clicked.connect(self.send_message)
        self.send_btn.setFixedSize(90, 42)
        self.send_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 6px;
                font-weight: bold;
                font-size: 12pt;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #BDBDBD;
            }
        """)
        btn_layout.addWidget(self.send_btn)
        
        self.stop_btn = QPushButton("停止")
        self.stop_btn.clicked.connect(self.stop_generation)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setFixedSize(90, 32)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                border: none;
                border-radius: 6px;
                font-size: 12pt;
            }
            QPushButton:hover {
                background-color: #da190b;
            }
            QPushButton:disabled {
                background-color: #BDBDBD;
            }
        """)
        btn_layout.addWidget(self.stop_btn)
        btn_layout.addStretch()
        
        input_row.addLayout(btn_layout)
        input_layout.addLayout(input_row)
        
        layout.addWidget(input_frame)
        
        widget.setLayout(layout)
        return widget
    
    def _create_config_panel(self):
        """创建配置面板"""
        widget = QWidget()
        widget.setMinimumWidth(360)
        widget.setFixedWidth(360)
        layout = QVBoxLayout()
        layout.setSpacing(14)
        layout.setContentsMargins(0, 0, 0, 0)
        
        title = QLabel("⚙️ 设置")
        title.setStyleSheet("font-size: 12pt; font-weight: bold; color: #333;")
        layout.addWidget(title)
        
        provider_group = QGroupBox("服务提供商")
        provider_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 12pt;
                border: 1px solid #D0D0D0;
                border-radius: 8px;
                margin-top: 12px;
                padding: 22px 15px 18px 15px;
                background-color: #FAFAFA;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #1976D2;
            }
        """)
        provider_layout = QVBoxLayout()
        provider_layout.setSpacing(12)
        provider_layout.setContentsMargins(5, 5, 5, 5)
        
        provider_label = QLabel("提供商")
        provider_label.setStyleSheet("color: #555; font-size: 12pt;")
        self.provider_combo = QComboBox()
        self.provider_combo.setMinimumHeight(36)
        self.provider_combo.setStyleSheet("font-size: 12pt;")
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
        api_key_label.setStyleSheet("color: #555; font-size: 12pt;")
        self.api_key_edit = QLineEdit()
        self.api_key_edit.setEchoMode(QLineEdit.Password)
        self.api_key_edit.setText(self.config.get('api_key', ''))
        self.api_key_edit.setPlaceholderText("输入API密钥")
        self.api_key_edit.setMinimumHeight(36)
        self.api_key_edit.setStyleSheet("font-size: 12pt;")
        provider_layout.addWidget(api_key_label)
        provider_layout.addWidget(self.api_key_edit)
        
        api_base_label = QLabel("API地址")
        api_base_label.setStyleSheet("color: #555; font-size: 12pt;")
        self.api_base_edit = QLineEdit()
        self.api_base_edit.setText(self.config.get('api_base', ''))
        self.api_base_edit.setPlaceholderText("留空使用默认地址")
        self.api_base_edit.setMinimumHeight(36)
        self.api_base_edit.setStyleSheet("font-size: 12pt;")
        provider_layout.addWidget(api_base_label)
        provider_layout.addWidget(self.api_base_edit)
        
        provider_group.setLayout(provider_layout)
        layout.addWidget(provider_group)
        
        model_group = QGroupBox("模型设置")
        model_group.setStyleSheet(provider_group.styleSheet())
        model_layout = QVBoxLayout()
        model_layout.setSpacing(12)
        model_layout.setContentsMargins(5, 5, 5, 5)
        
        model_label = QLabel("模型")
        model_label.setStyleSheet("color: #555; font-size: 12pt;")
        model_row = QHBoxLayout()
        model_row.setSpacing(8)
        
        self.model_combo = QComboBox()
        self.model_combo.setEditable(True)
        self.model_combo.setMinimumHeight(36)
        self.model_combo.setStyleSheet("font-size: 12pt;")
        self.update_model_list()
        current_model = self.config.get('model', '')
        if current_model:
            self.model_combo.setCurrentText(current_model)
        model_row.addWidget(self.model_combo, stretch=1)
        
        self.refresh_btn = QPushButton("🔄")
        self.refresh_btn.setFixedSize(40, 36)
        self.refresh_btn.setToolTip("刷新模型列表")
        self.refresh_btn.clicked.connect(self.refresh_models)
        model_row.addWidget(self.refresh_btn)
        model_layout.addWidget(model_label)
        model_layout.addLayout(model_row)
        
        temp_label = QLabel("温度 (Temperature)")
        temp_label.setStyleSheet("color: #555; font-size: 12pt;")
        self.temp_spin = QDoubleSpinBox()
        self.temp_spin.setRange(0.0, 2.0)
        self.temp_spin.setSingleStep(0.1)
        self.temp_spin.setValue(self.config.get('temperature', 0.7))
        self.temp_spin.setMinimumHeight(36)
        self.temp_spin.setStyleSheet("font-size: 12pt;")
        model_layout.addWidget(temp_label)
        model_layout.addWidget(self.temp_spin)
        
        tokens_label = QLabel("最大长度 (Max Tokens)")
        tokens_label.setStyleSheet("color: #555; font-size: 12pt;")
        self.max_tokens_spin = QSpinBox()
        self.max_tokens_spin.setRange(100, 32000)
        self.max_tokens_spin.setValue(self.config.get('max_tokens', 2048))
        self.max_tokens_spin.setMinimumHeight(36)
        self.max_tokens_spin.setStyleSheet("font-size: 12pt;")
        model_layout.addWidget(tokens_label)
        model_layout.addWidget(self.max_tokens_spin)
        
        model_group.setLayout(model_layout)
        layout.addWidget(model_group)
        
        prompt_group = QGroupBox("系统提示")
        prompt_group.setStyleSheet(provider_group.styleSheet())
        prompt_layout = QVBoxLayout()
        prompt_layout.setSpacing(5)
        prompt_layout.setContentsMargins(5, 5, 5, 5)
        
        self.system_prompt_edit = QTextEdit()
        self.system_prompt_edit.setPlainText(self.config.get('system_prompt', ''))
        self.system_prompt_edit.setMinimumHeight(90)
        self.system_prompt_edit.setMaximumHeight(110)
        self.system_prompt_edit.setStyleSheet("font-size: 12pt;")
        prompt_layout.addWidget(self.system_prompt_edit)
        
        prompt_group.setLayout(prompt_layout)
        layout.addWidget(prompt_group)
        
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(12)
        
        test_btn = QPushButton("🔗 测试连接")
        test_btn.clicked.connect(self.test_connection)
        test_btn.setMinimumHeight(44)
        test_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                border: none;
                border-radius: 6px;
                font-weight: bold;
                font-size: 12pt;
            }
            QPushButton:hover {
                background-color: #F57C00;
            }
        """)
        btn_layout.addWidget(test_btn)
        
        save_btn = QPushButton("💾 保存配置")
        save_btn.clicked.connect(self.save_config)
        save_btn.setMinimumHeight(44)
        save_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                border-radius: 6px;
                font-weight: bold;
                font-size: 12pt;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        btn_layout.addWidget(save_btn)
        
        layout.addLayout(btn_layout)
        layout.addStretch()
        
        widget.setLayout(layout)
        return widget
    
    def update_model_list(self, models=None):
        """更新模型列表"""
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
        """提供商改变时更新"""
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
            QTimer.singleShot(500, self.auto_refresh_ollama_models)
        else:
            provider_api_key = provider_config.get('api_key', '')
            self.api_key_edit.setText(provider_api_key)
            self.api_key_edit.setPlaceholderText("输入API密钥")
            self.api_key_edit.setEnabled(True)
    
    def auto_refresh_ollama_models(self):
        """自动刷新Ollama模型列表"""
        if self.provider_combo.currentData() != 'ollama':
            return
        
        self.refresh_btn.setEnabled(False)
        
        self.model_worker = ModelRefreshWorker(
            'ollama',
            self.api_base_edit.text(),
            ''
        )
        self.model_worker.models_ready.connect(self.on_models_ready)
        self.model_worker.start()
    
    def on_models_ready(self, models):
        """模型列表获取完成"""
        self.refresh_btn.setEnabled(True)
        if models:
            self.model_combo.clear()
            self.model_combo.addItems(sorted(dict.fromkeys(models)))
    
    def refresh_models(self):
        """刷新模型列表"""
        provider = self.provider_combo.currentData()
        api_base = self.api_base_edit.text()
        api_key = self.api_key_edit.text()
        
        self.refresh_btn.setEnabled(False)
        
        self.model_worker = ModelRefreshWorker(provider, api_base, api_key)
        self.model_worker.models_ready.connect(self.on_models_ready)
        self.model_worker.start()
    
    def save_config(self):
        """保存配置"""
        self.config.set('provider', self.provider_combo.currentData())
        self.config.set('api_key', self.api_key_edit.text())
        self.config.set('api_base', self.api_base_edit.text())
        self.config.set('model', self.model_combo.currentText())
        self.config.set('temperature', self.temp_spin.value())
        self.config.set('max_tokens', self.max_tokens_spin.value())
        self.config.set('system_prompt', self.system_prompt_edit.toPlainText())
        
        self.client = AIClient(self.config)
        
        QMessageBox.information(self, "成功", "配置已保存")
    
    def test_connection(self):
        """测试连接"""
        self.save_config()
        
        success, message = self.client.test_connection()
        
        if success:
            QMessageBox.information(self, "成功", message)
        else:
            QMessageBox.warning(self, "失败", message)
    
    def send_message(self):
        """发送消息"""
        message = self.input_edit.toPlainText().strip()
        if not message:
            return
        
        self.input_edit.clear()
        self.append_user_message(message)
        
        self.send_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.current_ai_content = ""
        
        self._ai_message_start_pos = None
        self.append_ai_message_start()
        
        self.worker = ChatWorker(self.client, message, stream=True)
        self.worker.response_ready.connect(self.on_response_chunk)
        self.worker.error_occurred.connect(self.on_error)
        self.worker.finished_chat.connect(self.on_chat_finished)
        self.worker.start()
    
    def stop_generation(self):
        """停止生成"""
        if self.worker and self.worker.isRunning():
            self.worker.terminate()
            self.append_system_message("已停止生成")
        self.on_chat_finished()
    
    def on_response_chunk(self, chunk):
        """收到响应块"""
        self.current_ai_content += chunk
        self.append_ai_content(chunk)
    
    def on_error(self, error):
        """发生错误"""
        self.append_error_message(error)
    
    def on_chat_finished(self):
        """聊天完成"""
        self.render_ai_markdown()
        self.send_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.worker = None
    
    def render_markdown(self, text):
        """渲染Markdown文本"""
        if MARKDOWN_AVAILABLE:
            try:
                html = markdown.markdown(
                    text,
                    extensions=['fenced_code', 'codehilite', 'tables', 'toc']
                )
                return html
            except:
                pass
        return self._escape_html(text).replace('\n', '<br>')
    
    def _escape_html(self, text):
        """转义HTML特殊字符"""
        return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    
    def append_user_message(self, content):
        """添加用户消息"""
        self._messages = getattr(self, '_messages', [])
        self._messages.append({'role': 'user', 'content': content})
        self._force_scroll_bottom = True
        self._render_all_messages()
    
    def append_ai_message_start(self):
        """开始AI消息"""
        self._messages = getattr(self, '_messages', [])
        model_name = self.model_combo.currentText()
        self._messages.append({'role': 'assistant', 'content': '', 'model': model_name})
    
    def append_ai_content(self, chunk):
        """追加AI消息内容并实时渲染"""
        if self._messages and self._messages[-1]['role'] == 'assistant':
            self._messages[-1]['content'] += chunk
        self._render_all_messages()
    
    def _render_all_messages(self):
        """渲染所有消息"""
        model_name = self.model_combo.currentText()
        
        html_parts = ['''
<style>
    body {
        font-size: 12pt;
        line-height: 1.6;
        color: #333;
    }
    code {
        background-color: #F5F5F5;
        color: #D32F2F;
        padding: 3px 8px;
        border-radius: 4px;
        font-family: Consolas, Monaco, monospace;
        font-size: 12pt;
    }
    pre {
        background-color: #263238;
        color: #EEFFFF;
        padding: 15px;
        border-radius: 8px;
        overflow-x: auto;
        font-family: Consolas, Monaco, monospace;
        font-size: 12pt;
        line-height: 1.5;
        margin: 10px 0;
    }
    pre code {
        background-color: transparent;
        color: #EEFFFF;
        padding: 0;
    }
    table {
        border-collapse: collapse;
        width: 100%;
        margin: 10px 0;
    }
    th, td {
        border: 1px solid #DDD;
        padding: 10px;
        text-align: left;
    }
    th {
        background-color: #F0F0F0;
    }
</style>
''']
        
        for msg in getattr(self, '_messages', []):
            if msg['role'] == 'user':
                html_parts.append(f'''
<div align="right" style="margin: 15px 0;">
    <div style="display: inline-block; text-align: left; padding: 12px 18px; background-color: #E3F2FD; border-radius: 12px; max-width: 80%;">
        <div style="color: #1976D2; font-weight: bold; margin-bottom: 10px; font-size: 13pt;">👤 你</div>
        <div style="color: #333; white-space: pre-wrap; font-size: 12pt;">{self._escape_html(msg['content'])}</div>
    </div>
</div>
''')
            else:
                rendered = self.render_markdown(msg['content'])
                ai_model = msg.get('model', model_name)
                html_parts.append(f'''
<div align="left" style="margin: 15px 0;">
    <div style="display: inline-block; text-align: left; padding: 15px 18px; background-color: #F5F5F5; border-radius: 12px; max-width: 80%;">
        <div style="color: #4CAF50; font-weight: bold; margin-bottom: 10px; font-size: 13pt;">🤖 AI <span style="font-size: 11pt; color: #888; font-weight: normal;">({self._escape_html(ai_model)})</span></div>
        <div style="color: #333; line-height: 1.7; font-size: 12pt;">{rendered}</div>
    </div>
</div>
''')
        
        scroll_bar = self.chat_display.verticalScrollBar()
        old_value = scroll_bar.value()
        at_bottom = old_value >= scroll_bar.maximum() - 30
        force_scroll_bottom = getattr(self, '_force_scroll_bottom', False)
        
        self.chat_display.setHtml(''.join(html_parts))
        
        QTimer.singleShot(0, lambda: self._restore_scroll_position(old_value, at_bottom, force_scroll_bottom))
        self._force_scroll_bottom = False

    def _restore_scroll_position(self, old_value, at_bottom, force_scroll_bottom=False):
        scroll_bar = self.chat_display.verticalScrollBar()
        if force_scroll_bottom or at_bottom:
            scroll_bar.setValue(scroll_bar.maximum())
        else:
            scroll_bar.setValue(min(old_value, scroll_bar.maximum()))
    
    def render_ai_markdown(self):
        """渲染AI消息的Markdown（完成时调用）"""
        pass
    
    def append_system_message(self, content):
        """添加系统消息"""
        cursor = self.chat_display.textCursor()
        cursor.movePosition(cursor.End)
        
        html = f'''
<div style="margin: 15px 0; text-align: center;">
    <span style="background-color: #FFF3E0; color: #FF9800; padding: 6px 18px; border-radius: 15px; font-size: 12pt;">
        ⚙️ {self._escape_html(content)}
    </span>
</div>
'''
        cursor.insertHtml(html)
        self.chat_display.setTextCursor(cursor)
    
    def append_error_message(self, content):
        """添加错误消息"""
        cursor = self.chat_display.textCursor()
        cursor.movePosition(cursor.End)
        
        html = f'''
<div style="margin: 15px 0; padding: 12px 18px; background-color: #FFEBEE; border-radius: 12px;">
    <div style="color: #f44336; font-weight: bold; margin-bottom: 8px; font-size: 13pt;">❌ 错误</div>
    <div style="color: #c62828; white-space: pre-wrap; font-size: 12pt;">{self._escape_html(content)}</div>
</div>
'''
        cursor.insertHtml(html)
        self.chat_display.setTextCursor(cursor)
    
    def clear_chat(self):
        """清空聊天"""
        self._messages = []
        self.chat_display.clear()
        self.config.clear_history()
    
    def eventFilter(self, obj, event):
        if obj == self.input_edit:
            if self.input_drop_helper and self.input_drop_helper.eventFilter(obj, event):
                return True
            if event.type() == event.KeyPress:
                if event.key() == Qt.Key_Return and not event.modifiers() & Qt.ShiftModifier:
                    self.send_message()
                    return True
        return super().eventFilter(obj, event)
    
    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            self.worker.terminate()
        if self.model_worker and self.model_worker.isRunning():
            self.model_worker.terminate()
        event.accept()
