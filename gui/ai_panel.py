"""
AI分析面板
=========
嵌入主窗口的AI分析面板
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QTextBrowser, QFrame, QApplication, QGroupBox,
    QSplitter
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QMetaObject, Q_ARG, QTimer
from PyQt5.QtGui import QFont

from utils.ai_assistant import AIConfig, AIClient
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
    
    def __init__(self, client, message, system_prompt=None, stream=True):
        super().__init__()
        self.client = client
        self.message = message
        self.system_prompt = system_prompt
        self.stream = stream
        self._is_stopped = False
    
    def run(self):
        try:
            for chunk in self.client.chat(self.message, self.stream, self.system_prompt):
                if self._is_stopped:
                    break
                if chunk.startswith("错误") or chunk.startswith("API错误") or chunk.startswith("网络错误") or chunk.startswith("无法连接") or chunk.startswith("请求失败") or chunk.startswith("请求超时") or chunk.startswith("[错误:"):
                    self.error_occurred.emit(chunk)
                else:
                    self.response_ready.emit(chunk)
        except Exception as e:
            import traceback
            error_msg = f"{str(e)}\n{traceback.format_exc()}"
            self.error_occurred.emit(error_msg)
        finally:
            self.finished_chat.emit()
    
    def stop(self):
        self._is_stopped = True


class AIAssistantPanel(QWidget):
    """AI分析面板 - 嵌入主窗口"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.config = AIConfig()
        self.client = AIClient(self.config)
        self.worker = None
        self.input_drop_helper = None
        self.current_ai_content = ""
        self._messages = []
        self._suppress_scroll_tracking = False
        self._tracked_scroll_value = 0
        self._tracked_at_bottom = True
        self._render_revision = 0
        
        self.setup_ui()
        install_plain_text_copy(self)
        self.input_drop_helper = TextFileDropHelper(self, self.input_edit)
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # 创建分割器，上方是系统提示词，下方是聊天区域
        splitter = QSplitter(Qt.Vertical)
        
        # 系统提示词区域
        system_group = QGroupBox("系统提示词")
        system_group.setStyleSheet("""
            QGroupBox {
                font-size: 10pt;
                font-weight: bold;
                border: 1px solid #ccc;
                border-radius: 4px;
                margin-top: 8px;
                padding-top: 8px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        system_layout = QVBoxLayout(system_group)
        system_layout.setContentsMargins(8, 8, 8, 8)
        
        self.system_prompt_edit = QTextEdit()
        self.system_prompt_edit.setPlaceholderText(
            "在此输入系统提示词，用于指导AI的行为和回答风格...\n"
            "例如：你是一个CTF密码学专家，擅长分析和破解各种加密算法。"
        )
        self.system_prompt_edit.setFont(QFont("Microsoft YaHei", 9))
        self.system_prompt_edit.setStyleSheet("""
            QTextEdit {
                border-radius: 4px;
            }
        """)
        self.system_prompt_edit.setMaximumHeight(100)
        system_layout.addWidget(self.system_prompt_edit)
        
        splitter.addWidget(system_group)
        
        # 聊天区域
        chat_widget = QWidget()
        chat_layout = QVBoxLayout(chat_widget)
        chat_layout.setSpacing(8)
        chat_layout.setContentsMargins(0, 0, 0, 0)
        
        # 聊天显示区域
        header = QHBoxLayout()
        title = QLabel("AI分析")
        title.setStyleSheet("font-size: 11pt; font-weight: bold; color: #333;")
        header.addWidget(title)
        header.addStretch()
        
        clear_btn = QPushButton("清空对话")
        clear_btn.setFixedSize(150, 50)
        clear_btn.clicked.connect(self.clear_chat)
        header.addWidget(clear_btn)
        chat_layout.addLayout(header)
        
        self.chat_display = QTextBrowser()
        self.chat_display.setReadOnly(True)
        self.chat_display.setFont(QFont("Microsoft YaHei", 10))
        self.chat_display.setStyleSheet("""
            QTextBrowser {
                background-color: #FAFAFA;
                border: 1px solid #E0E0E0;
                border-radius: 6px;
                padding: 8px;
            }
        """)
        self.chat_display.setOpenExternalLinks(True)
        self.chat_display.verticalScrollBar().valueChanged.connect(self._on_chat_scroll_changed)
        chat_layout.addWidget(self.chat_display, stretch=1)
        
        # 用户输入区域
        input_frame = QFrame()
        input_frame.setStyleSheet("""
            QFrame {
                background-color: #FFFFFF;
                border: 1px solid #E0E0E0;
                border-radius: 6px;
            }
        """)
        input_layout = QVBoxLayout(input_frame)
        input_layout.setContentsMargins(8, 8, 8, 8)
        input_layout.setSpacing(6)
        
        self.input_edit = QTextEdit()
        self.input_edit.setPlaceholderText("输入要分析的内容，Enter发送...")
        self.input_edit.setFont(QFont("Microsoft YaHei", 10))
        self.input_edit.setStyleSheet("border: none; background: transparent;")
        self.input_edit.setMaximumHeight(80)
        self.input_edit.installEventFilter(self)
        input_layout.addWidget(self.input_edit)
        
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        
        self.send_btn = QPushButton("发送")
        self.send_btn.setFixedSize(100, 40)
        self.send_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #BDBDBD;
            }
        """)
        self.send_btn.clicked.connect(self.send_message)
        btn_row.addWidget(self.send_btn)
        
        self.stop_btn = QPushButton("停止")
        self.stop_btn.setFixedSize(100, 40)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                border: none;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #da190b;
            }
            QPushButton:disabled {
                background-color: #BDBDBD;
            }
        """)
        self.stop_btn.clicked.connect(self.stop_generation)
        self.stop_btn.setEnabled(False)
        btn_row.addWidget(self.stop_btn)
        
        input_layout.addLayout(btn_row)
        chat_layout.addWidget(input_frame)
        
        splitter.addWidget(chat_widget)
        splitter.setSizes([120, 500])
        
        layout.addWidget(splitter)
    
    def send_message(self):
        message = self.input_edit.toPlainText().strip()
        if not message:
            return
        
        # 获取系统提示词
        system_prompt = self.system_prompt_edit.toPlainText().strip()
        if not system_prompt:
            system_prompt = None
        
        self.input_edit.clear()
        
        self._messages.append({'role': 'user', 'content': message})
        self._tracked_at_bottom = True
        self._render_messages()
        
        self.send_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.current_ai_content = ""
        
        self._messages.append({'role': 'assistant', 'content': ''})
        
        self.worker = ChatWorker(self.client, message, system_prompt, stream=True)
        self.worker.response_ready.connect(self.on_response_chunk)
        self.worker.error_occurred.connect(self.on_error)
        self.worker.finished_chat.connect(self.on_chat_finished)
        self.worker.start()
    
    def stop_generation(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.terminate()
            self.worker.wait(1000)
        self.on_chat_finished()
    
    def on_response_chunk(self, chunk):
        try:
            self.current_ai_content += chunk
            if self._messages and self._messages[-1]['role'] == 'assistant':
                self._messages[-1]['content'] = self.current_ai_content
            self._render_messages()
        except Exception as e:
            print(f"Error in on_response_chunk: {e}")
    
    def on_error(self, error):
        try:
            if self._messages:
                self._messages[-1]['content'] = f"❌ 错误: {error}"
            self._render_messages()
        except Exception as e:
            print(f"Error in on_error: {e}")
    
    def on_chat_finished(self):
        try:
            self.send_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.worker = None
        except Exception as e:
            print(f"Error in on_chat_finished: {e}")
    
    def _render_messages(self):
        html_parts = ['''
<style>
    body { font-size: 10pt; line-height: 1.5; color: #333; }
    code { background-color: #F0F0F0; padding: 2px 6px; border-radius: 3px; color: #D32F2F; font-family: Consolas, Monaco, monospace; }
    pre { background-color: #1E1E1E; color: #D4D4D4; padding: 12px; border-radius: 6px; overflow-x: auto; margin: 8px 0; }
    pre code { background-color: transparent; color: #D4D4D4; padding: 0; }
</style>
''']

        for msg in self._messages:
            if msg['role'] == 'user':
                html_parts.append(f'''
<div align="right" style="margin:6px 0;">
  <table style="margin-left:auto;background:#D6EAF8;border-radius:8px;padding:8px 12px;"><tr><td>
    <div style="color:#1A5276;font-weight:bold;font-size:9pt;">你</div>
    <div style="white-space:pre-wrap;color:#1C2833;">{self._escape_html(msg['content'])}</div>
  </td></tr></table>
</div>
''')
            else:
                content = self._render_markdown(msg['content'])
                html_parts.append(f'''
<div align="left" style="margin:6px 0;">
  <table style="background:#E8F5E9;border:1px solid #81C784;border-radius:8px;padding:8px 12px;"><tr><td>
    <div style="color:#2E7D32;font-weight:bold;font-size:9pt;">AI</div>
    <div style="line-height:1.6;color:#1C2833;">{content}</div>
  </td></tr></table>
</div>
''')
        
        old_value = self._tracked_scroll_value
        at_bottom = self._tracked_at_bottom
        self._render_revision += 1
        revision = self._render_revision
        
        self._suppress_scroll_tracking = True
        self.chat_display.setHtml(''.join(html_parts))

        QTimer.singleShot(0, lambda: self._restore_scroll_position(old_value, at_bottom, revision))

    def _on_chat_scroll_changed(self, value):
        if self._suppress_scroll_tracking:
            return
        scroll_bar = self.chat_display.verticalScrollBar()
        self._tracked_scroll_value = value
        self._tracked_at_bottom = value >= scroll_bar.maximum() - 30

    def _restore_scroll_position(self, old_value, at_bottom, revision):
        if revision != self._render_revision:
            return
        scroll_bar = self.chat_display.verticalScrollBar()
        if at_bottom:
            scroll_bar.setValue(scroll_bar.maximum())
        else:
            scroll_bar.setValue(min(old_value, scroll_bar.maximum()))
        self._tracked_scroll_value = scroll_bar.value()
        self._tracked_at_bottom = scroll_bar.value() >= scroll_bar.maximum() - 30
        self._suppress_scroll_tracking = False
    
    def _render_markdown(self, text):
        if MARKDOWN_AVAILABLE:
            try:
                return markdown.markdown(text, extensions=['fenced_code', 'codehilite', 'tables'])
            except:
                pass
        return self._escape_html(text).replace('\n', '<br>')
    
    def _escape_html(self, text):
        return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    
    def clear_chat(self):
        self._messages = []
        self.chat_display.clear()
        self._tracked_scroll_value = 0
        self._tracked_at_bottom = True
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
    
    def reload_config(self):
        """重新加载配置"""
        self.config = AIConfig()
        self.client = AIClient(self.config)
