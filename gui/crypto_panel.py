"""
加解密面板模块 (Crypto Panel)
========================
CTF加解密工具的加解密功能面板

本模块包含:
- CryptoPanel类: 加解密面板，提供输入/输出界面和算法选择
"""

import sys
import json
import re
from urllib.parse import unquote, urlparse
from pathlib import Path
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QSplitter, QMessageBox, QGroupBox, QFrame,
    QApplication, QCheckBox, QComboBox, QSpinBox,
    QLineEdit, QScrollArea, QGridLayout, QDialog, QListWidget,
    QMenu, QAction, QMenuBar, QFileDialog
)
from PyQt5.QtCore import Qt, QTimer, QEvent
from PyQt5.QtGui import QFont, QColor, QTextCharFormat, QBrush, QTextCursor, QTextDocument, QSyntaxHighlighter

from utils.history import HistoryManager
from utils.ai_auto_analyze import AIAutoAnalyzer, PatternAnalyzer, AutoDecryptor
from utils.recursive_decryptor import AsyncRecursiveDecryptor, RecordManager, DecryptRecord
from utils.recursive_features import feature_score
from core.constants import CATEGORY_NAMES, CATEGORY_DESC
from core.crypto_loader import CryptoLoader
from .settings_dialog import SettingsDialog
from .base_converter import BaseConverterDialog
from .rsa_dialog import RSADialog
from .ecc_dialog import ECCDialog
from .lcg_dialog import LCGDialog
from .symmetric_dialog import SymmetricDialog
from .ai_config_dialog import AIConfigDialog
from .text_tools_dialog import TextToolsDialog
from .clipboard_utils import copy_plain_text, install_plain_text_copy


class MatchHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.patterns = []
        self.case_sensitive = False
        
    def set_patterns(self, patterns, case_sensitive=False):
        self.patterns = patterns
        self.case_sensitive = case_sensitive
        self.rehighlight()
    
    def highlightBlock(self, text):
        for pattern_info in self.patterns:
            pattern = pattern_info['pattern']
            bg_color = pattern_info['bg_color']
            fg_color = pattern_info['fg_color']
            
            search_text = text if self.case_sensitive else text.lower()
            search_pattern = pattern if self.case_sensitive else pattern.lower()
            
            start = 0
            while True:
                pos = search_text.find(search_pattern, start)
                if pos == -1:
                    break
                
                fmt = QTextCharFormat()
                fmt.setBackground(QColor(bg_color))
                fmt.setForeground(QColor(fg_color))
                fmt.setFontWeight(75)
                
                self.setFormat(pos, len(pattern), fmt)
                start = pos + 1


class CryptoPanel(QWidget):
    """
    加解密面板类
    包含输入/输出区域、参数设置和算法选择功能
    """
    
    def __init__(self, parent=None, main_window=None, panel_mode=None):
        super().__init__(parent)
        
        self.main_window = main_window
        self.panel_mode = panel_mode
        
        self.encrypt_modules = {}
        self.decrypt_modules = {}
        
        self.base_path = Path(__file__).parent.parent
        self.algorithms_path = self.base_path / "algorithms"
        self.crypto_loader = CryptoLoader(self.base_path)
        
        self.current_mode = None
        self.current_module = None
        self.current_algo_name = None
        self.param_widgets = {}
        
        self.auto_copy = False
        self.auto_swap = False
        
        self.ai_analyzer = AIAutoAnalyzer()
        self.ai_analyzer.analysis_complete.connect(self.on_analysis_complete)
        self.ai_analyzer.analysis_error.connect(self.on_analysis_error)
        self.ai_analyzer.analysis_chunk.connect(self.on_analysis_chunk)
        self.streaming_content = ""
        
        self.input_bg_color = "#FFFFFF"
        self.output_bg_color = "#F5F5F5"
        self.param_bg_color = "#FAFAFA"
        
        self.input_history = HistoryManager(max_size=50)
        self.last_saved_content = ""
        
        self.history_timer = QTimer()
        self.history_timer.setSingleShot(True)
        self.history_timer.timeout.connect(self.save_input_history)

        self.auto_execute_timer = QTimer()
        self.auto_execute_timer.setSingleShot(True)
        self.auto_execute_timer.timeout.connect(self.auto_execute)
        self._loading_file_reference = False
        
        self.match_pattern = ""
        self.last_output_text = ""
        self.case_sensitive = False
        self.match_positions = []
        self._match_highlighter_patterns = []
        self.search_positions = []
        
        self.record_manager = RecordManager()
        self.async_decryptor = None
        self.recursive_max_depth = 10
        self.recursive_max_workers = 4
        self.recursive_max_tasks = 1000
        self.recursive_max_display_results = 100
        self.recursive_bruteforce = True
        self.recursive_custom_features = []
        self.recursive_disabled_builtin_features = []
        
        self.init_ui()
        install_plain_text_copy(self)
        self.load_all_modules()
        if self.panel_mode in ('encrypt', 'decrypt'):
            self.current_mode = self.panel_mode
        self.apply_colors()
    
    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(10, 10, 10, 10)
        
        main_splitter = QSplitter(Qt.Horizontal)
        
        # 左侧区域 - 参数面板 + 输入/输出
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setSpacing(8)
        left_layout.setContentsMargins(0, 0, 0, 0)
        
        # 参数面板
        self.param_widget = QWidget()
        self.param_widget.setStyleSheet("""
            QWidget {
                background-color: #f5f5f5;
                border: 1px solid #ddd;
                border-radius: 5px;
                padding: 5px;
            }
        """)
        self.param_layout = QVBoxLayout(self.param_widget)
        self.param_layout.setSpacing(5)
        self.param_layout.setContentsMargins(8, 8, 8, 8)
        self.param_widget.hide()
        
        left_layout.addWidget(self.param_widget)
        
        # 输入区域
        input_group = QGroupBox()
        input_group.setStyleSheet("QGroupBox { font-weight: bold; font-size: 11pt; border: 1px solid #ccc; border-radius: 5px; margin-top: 10px; padding-top: 10px; } QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }")
        
        input_outer_layout = QVBoxLayout(input_group)
        input_outer_layout.setContentsMargins(8, 15, 8, 8)
        
        input_header = QWidget()
        input_header.setStyleSheet("background: transparent;")
        input_header_layout = QHBoxLayout(input_header)
        input_header_layout.setContentsMargins(0, 0, 0, 5)
        
        input_label = QLabel("输入")
        input_label.setStyleSheet("font-weight: bold; font-size: 11pt;")
        input_header_layout.addWidget(input_label)
        
        self.ai_analyze_btn = QPushButton("AI分析")
        self.ai_analyze_btn.setFixedHeight(28)
        self.ai_analyze_btn.clicked.connect(self.on_ai_analyze_clicked)
        input_header_layout.addWidget(self.ai_analyze_btn)
        if self.panel_mode == 'encrypt':
            self.ai_analyze_btn.hide()
        
        self.one_click_btn = QPushButton("一键解密")
        self.one_click_btn.setFixedHeight(28)
        self.one_click_btn.clicked.connect(self.one_click_decrypt)
        input_header_layout.addWidget(self.one_click_btn)
        if self.panel_mode == 'encrypt':
            self.one_click_btn.hide()
        
        self.recursive_decrypt_btn = QPushButton("递归解密")
        self.recursive_decrypt_btn.setFixedHeight(28)
        self.recursive_decrypt_btn.setStyleSheet("""
            QPushButton {
                background-color: #999999;
                color: white;
                border: none;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #111111;
            }
            QPushButton:disabled {
                background-color: #666666;
            }
        """)
        self.recursive_decrypt_btn.clicked.connect(self.start_recursive_decrypt)
        input_header_layout.addWidget(self.recursive_decrypt_btn)
        if self.panel_mode == 'encrypt':
            self.recursive_decrypt_btn.hide()

        self.import_input_btn = QPushButton("导入内容")
        self.import_input_btn.setFixedHeight(28)
        self.import_input_btn.setToolTip("导入文本文件；无后缀或二进制文件自动转为十六进制")
        self.import_input_btn.clicked.connect(self.import_input_file)
        input_header_layout.addWidget(self.import_input_btn)
        
        self.clear_input_btn = QPushButton("清空")
        self.clear_input_btn.setFixedHeight(28)
        self.clear_input_btn.clicked.connect(lambda: self.input_text.clear())
        input_header_layout.addWidget(self.clear_input_btn)

        self.text_tools_btn = QPushButton("文本工具")
        self.text_tools_btn.setFixedHeight(28)
        self.text_tools_btn.clicked.connect(self.open_text_tools_dialog)
        input_header_layout.addWidget(self.text_tools_btn)
        
        input_header_layout.addStretch()
        input_outer_layout.addWidget(input_header)
        
        self.input_text = QTextEdit()
        if self.panel_mode == 'encrypt':
            placeholder = "请输入要加密的内容，或导入文件内容..."
        elif self.panel_mode == 'decrypt':
            placeholder = "请输入要解密的内容，或导入密文文件..."
        else:
            placeholder = "请输入要加密/解密的内容..."
        self.input_text.setPlaceholderText(placeholder)
        self.input_text.setFont(QFont("Consolas", 11))
        self.input_text.setLineWrapMode(QTextEdit.WidgetWidth)
        self.input_text.textChanged.connect(self.on_input_text_changed)
        self.input_text.setStyleSheet("border: none;")
        input_outer_layout.addWidget(self.input_text)
        
        self.input_text.installEventFilter(self)
        self.input_text.setAcceptDrops(True)
        
        left_layout.addWidget(input_group, stretch=1)
        
        # 输出区域
        output_group = QGroupBox()
        output_group.setStyleSheet("QGroupBox { font-weight: bold; font-size: 11pt; border: 1px solid #ccc; border-radius: 5px; margin-top: 10px; padding-top: 10px; } QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }")
        
        output_outer_layout = QVBoxLayout(output_group)
        output_outer_layout.setContentsMargins(8, 15, 8, 8)
        
        output_header = QWidget()
        output_header.setStyleSheet("background: transparent;")
        output_header_layout = QVBoxLayout(output_header)
        output_header_layout.setContentsMargins(0, 0, 0, 5)
        output_header_layout.setSpacing(3)
        
        output_header_row1 = QWidget()
        output_header_row1.setStyleSheet("background: transparent;")
        output_header_row1_layout = QHBoxLayout(output_header_row1)
        output_header_row1_layout.setContentsMargins(0, 0, 0, 0)
        
        output_label = QLabel("输出")
        output_label.setStyleSheet("font-weight: bold; font-size: 11pt;")
        output_header_row1_layout.addWidget(output_label)
        
        self.swap_btn = QPushButton("替换到输入")
        self.swap_btn.setFixedHeight(26)
        self.swap_btn.clicked.connect(self.swap_io)
        output_header_row1_layout.addWidget(self.swap_btn)
        
        self.copy_btn = QPushButton("复制")
        self.copy_btn.setFixedHeight(26)
        self.copy_btn.clicked.connect(self.copy_output)
        output_header_row1_layout.addWidget(self.copy_btn)
        
        self.clear_output_btn = QPushButton("清空")
        self.clear_output_btn.setFixedHeight(26)
        self.clear_output_btn.clicked.connect(lambda: self.output_text.clear())
        output_header_row1_layout.addWidget(self.clear_output_btn)
        
        output_header_row1_layout.addStretch()
        
        self.case_sensitive_cb = QCheckBox("区分大小写")
        self.case_sensitive_cb.setStyleSheet("""
            QCheckBox {
                font-size: 10pt;
                spacing: 5px;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
            }
        """)
        self.case_sensitive_cb.stateChanged.connect(self.on_case_sensitive_changed)
        output_header_row1_layout.addWidget(self.case_sensitive_cb)
        
        output_header_layout.addWidget(output_header_row1)
        
        output_header_row2 = QWidget()
        output_header_row2.setStyleSheet("background: transparent;")
        output_header_row2_layout = QHBoxLayout(output_header_row2)
        output_header_row2_layout.setContentsMargins(0, 0, 0, 0)
        
        match_label = QLabel("匹配:")
        match_label.setStyleSheet("font-size: 10pt;")
        output_header_row2_layout.addWidget(match_label)
        
        self.match_input = QLineEdit()
        self.match_input.setPlaceholderText("输入匹配内容，多个用分号(;)分隔...")
        self.match_input.setFixedHeight(26)
        self.match_input.setText("flag;ctf;key")
        self.match_pattern = "flag;ctf;key"
        self.match_input.textChanged.connect(self.on_match_pattern_changed)
        output_header_row2_layout.addWidget(self.match_input)
        
        self.match_prev_btn = QPushButton("◀ 上一个")
        self.match_prev_btn.setFixedHeight(26)
        self.match_prev_btn.setToolTip("跳转到上一个匹配项")
        self.match_prev_btn.clicked.connect(self.find_prev_match)
        output_header_row2_layout.addWidget(self.match_prev_btn)
        
        self.match_next_btn = QPushButton("下一个 ▶")
        self.match_next_btn.setFixedHeight(26)
        self.match_next_btn.setToolTip("跳转到下一个匹配项")
        self.match_next_btn.clicked.connect(self.find_next_match)
        output_header_row2_layout.addWidget(self.match_next_btn)
        
        self.match_count_label = QLabel("")
        self.match_count_label.setStyleSheet("font-size: 10pt; color: #333; min-width: 80px;")
        output_header_row2_layout.addWidget(self.match_count_label)
        
        output_header_layout.addWidget(output_header_row2)
        
        output_header_row3 = QWidget()
        output_header_row3.setStyleSheet("background: transparent;")
        output_header_row3_layout = QHBoxLayout(output_header_row3)
        output_header_row3_layout.setContentsMargins(0, 2, 0, 0)
        
        quick_label = QLabel("快捷:")
        quick_label.setStyleSheet("font-size: 9pt; color: #888;")
        output_header_row3_layout.addWidget(quick_label)
        
        self.quick_tags = ['flag', 'ctf', 'key', 'password', 'secret', 'admin', 'root']
        self.tag_buttons = {}
        
        for tag in self.quick_tags:
            btn = QPushButton(tag)
            btn.setCheckable(True)
            btn.setFixedHeight(22)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setStyleSheet("""
                QPushButton {
                    font-size: 9pt;
                    padding: 2px 8px;
                    border-radius: 3px;
                    background-color: #E0E0E0;
                    border: 1px solid #BDBDBD;
                }
                QPushButton:checked {
                    background-color: #FFEB3B;
                    border: 1px solid #FFC107;
                    color: #333;
                }
                QPushButton:hover {
                    background-color: #BDBDBD;
                }
                QPushButton:checked:hover {
                    background-color: #FDD835;
                }
            """)
            btn.clicked.connect(lambda checked, t=tag: self.toggle_quick_tag(t))
            output_header_row3_layout.addWidget(btn)
            self.tag_buttons[tag] = btn
        
        for tag in ['flag', 'ctf', 'key']:
            self.tag_buttons[tag].setChecked(True)
        
        output_header_row3_layout.addStretch()
        
        clear_tags_btn = QPushButton("清除")
        clear_tags_btn.setFixedHeight(22)
        clear_tags_btn.setCursor(Qt.PointingHandCursor)
        clear_tags_btn.setStyleSheet("""
            QPushButton {
                font-size: 9pt;
                padding: 2px 8px;
                border-radius: 3px;
                background-color: transparent;
                border: 1px solid #BDBDBD;
                color: #666;
            }
            QPushButton:hover {
                background-color: #FFCDD2;
                border-color: #EF5350;
                color: #C62828;
            }
        """)
        clear_tags_btn.clicked.connect(self.clear_all_tags)
        output_header_row3_layout.addWidget(clear_tags_btn)
        
        output_header_layout.addWidget(output_header_row3)

        output_header_row4 = QWidget()
        output_header_row4.setStyleSheet("background: transparent;")
        output_header_row4_layout = QHBoxLayout(output_header_row4)
        output_header_row4_layout.setContentsMargins(0, 2, 0, 0)

        search_label = QLabel("搜索:")
        search_label.setStyleSheet("font-size: 10pt;")
        output_header_row4_layout.addWidget(search_label)

        self.output_search_input = QLineEdit()
        self.output_search_input.setPlaceholderText("在输出中搜索...")
        self.output_search_input.setFixedHeight(26)
        self.output_search_input.textChanged.connect(self.on_output_search_changed)
        output_header_row4_layout.addWidget(self.output_search_input)

        self.output_search_prev_btn = QPushButton("◀ 上一个")
        self.output_search_prev_btn.setFixedHeight(26)
        self.output_search_prev_btn.clicked.connect(self.find_prev_search_result)
        output_header_row4_layout.addWidget(self.output_search_prev_btn)

        self.output_search_next_btn = QPushButton("下一个 ▶")
        self.output_search_next_btn.setFixedHeight(26)
        self.output_search_next_btn.clicked.connect(self.find_next_search_result)
        output_header_row4_layout.addWidget(self.output_search_next_btn)

        self.output_search_count_label = QLabel("")
        self.output_search_count_label.setStyleSheet("font-size: 10pt; color: #333; min-width: 80px;")
        output_header_row4_layout.addWidget(self.output_search_count_label)

        output_header_layout.addWidget(output_header_row4)
        output_outer_layout.addWidget(output_header)
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFont(QFont("Consolas", 11))
        self.output_text.setLineWrapMode(QTextEdit.WidgetWidth)
        self.output_text.setStyleSheet("QTextEdit { border: none; background-color: #FAFAFA; }")
        output_outer_layout.addWidget(self.output_text)
        
        self.highlighter = MatchHighlighter(self.output_text.document())
        
        # 右侧区域 - 输出面板
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setSpacing(8)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.addWidget(output_group, stretch=1)
        
        main_splitter.addWidget(left_widget)
        main_splitter.addWidget(right_widget)
        main_splitter.setSizes([600, 600])
        
        main_layout.addWidget(main_splitter)
    
    def on_ai_analyze_clicked(self):
        """AI分析按钮点击 - 流式输出"""
        if not AIConfigDialog.is_configured():
            dialog = AIConfigDialog(self, require_config=True)
            if dialog.exec_() != dialog.Accepted:
                return

        text = self.input_text.toPlainText().strip()
        if not text:
            self.show_status_message("请先输入内容")
            return

        self.ai_analyze_btn.setEnabled(False)
        self.ai_analyze_btn.setText("分析中...")
        self.streaming_content = ""
        self.set_output_with_highlight("【AI分析中...】\n\n")
        # 根据当前算法选择分析上下文
        algo_context = 'default'
        if self.current_algo_name:
            name_lower = self.current_algo_name.lower()
            if 'rsa' in name_lower:
                algo_context = 'rsa'
            elif 'ecc' in name_lower or '椭圆' in name_lower:
                algo_context = 'ecc'
            elif any(k in name_lower for k in ['caesar', 'vigenere', 'playfair', 'rail', 'affine',
                                                  'atbash', 'bacon', 'hill', 'morse', 'rot']):
                algo_context = 'classical'
        self.ai_analyzer.analyze_async(text, algo_context)
    
    def show_status_message(self, message):
        """显示状态消息"""
        if self.main_window:
            self.main_window.statusBar().showMessage(message)
    
    def on_input_text_changed(self):
        if not self._loading_file_reference:
            if self._replace_file_reference_input():
                return
        self.history_timer.start(500)
        self.auto_execute_timer.start(300)
        self.update_cursor_status()
    
    def update_cursor_status(self):
        cursor = self.input_text.textCursor()
        text = self.input_text.toPlainText()
        length = len(text)
        
        if cursor.hasSelection():
            select_length = abs(cursor.selectionStart() - cursor.selectionEnd())
            status_text = f"字符数: {length} | 选中: {select_length} | 行列: {cursor.blockNumber() + 1}, {cursor.columnNumber() + 1}"
        else:
            status_text = f"字符数: {length} | 行列: {cursor.blockNumber() + 1}, {cursor.columnNumber() + 1}"
        
        if self.main_window:
            self.main_window.status_label.setText(status_text)
    
    def on_analysis_chunk(self, chunk: str):
        """接收流式分析内容"""
        self.streaming_content += chunk
        # 实时更新输出区域，显示分析过程
        display_content = f"【AI分析中...】\n\n{self.streaming_content}"
        self.output_text.setPlainText(display_content)
        # 滚动到底部
        scrollbar = self.output_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def on_analysis_complete(self, result: dict):
        """分析完成回调"""
        self.ai_analyze_btn.setEnabled(True)
        self.ai_analyze_btn.setText("AI分析")

        if not result.get('success'):
            # 如果分析失败但有流式内容，保留显示
            if self.streaming_content:
                self.output_text.setPlainText(f"【AI分析过程】\n\n{self.streaming_content}\n\n[分析未能完成]")
            return

        analysis = result.get('result', {})
        algorithm = analysis.get('algorithm', '')
        confidence = analysis.get('confidence', 0)
        description = analysis.get('description', '')
        all_results = result.get('all_results', [])

        if confidence >= 0.7 and algorithm:
            success, decrypt_result = AutoDecryptor.try_decrypt(
                self.input_text.toPlainText(),
                algorithm,
                self.decrypt_modules
            )

            if success:
                # 构建最终结果，包含分析过程和解密结果
                final_output = f"【AI自动分析解密结果】\n"
                if self.streaming_content:
                    final_output += f"\n【分析过程】\n{self.streaming_content}\n"
                    final_output += f"{'─' * 40}\n"
                final_output += f"检测类型: {analysis.get('type', 'Unknown')}\n"
                final_output += f"置信度: {confidence:.0%}\n"
                final_output += f"算法: {algorithm}\n"
                final_output += f"说明: {description}\n"
                final_output += f"{'─' * 40}\n"
                final_output += f"{decrypt_result}"

                self.set_output_with_highlight(final_output)
                self.show_status_message(f"AI自动解密成功: {algorithm}")
            else:
                self._show_analysis_suggestions(analysis, all_results)
        else:
            self._show_analysis_suggestions(analysis, all_results)
    
    def _show_analysis_suggestions(self, analysis: dict, all_results: list):
        """显示分析建议"""
        suggestions = []

        # 如果有流式内容，先显示分析过程
        if self.streaming_content:
            suggestions.append("【AI分析过程】")
            suggestions.append(self.streaming_content)
            suggestions.append("")
            suggestions.append("=" * 40)
            suggestions.append("")

        suggestions.append("【AI分析建议】")
        suggestions.append(f"检测类型: {analysis.get('type', 'Unknown')}")
        suggestions.append(f"置信度: {analysis.get('confidence', 0):.0%}")
        suggestions.append(f"说明: {analysis.get('description', '')}")
        suggestions.append("")

        if all_results:
            suggestions.append("【可能的解密方法】")
            for r in all_results[:5]:
                suggestions.append(f"  • {r.get('type', 'Unknown')} (置信度: {r.get('confidence', 0):.0%})")
                suggestions.append(f"    算法: {r.get('algorithm', '')}")

        suggestions.append("")
        suggestions.append("提示: 请从菜单选择对应的解密算法进行尝试")

        self.set_output_with_highlight('\n'.join(suggestions))
        self.show_status_message("AI分析完成，请选择解密算法")
    
    def on_analysis_error(self, error_msg: str):
        """分析错误回调"""
        self.ai_analyze_btn.setEnabled(True)
        self.ai_analyze_btn.setText("AI分析")
        self.show_status_message(f"AI分析: {error_msg}")
    
    def save_input_history(self):
        current_content = self.input_text.toPlainText()
        if current_content != self.last_saved_content:
            self.input_history.push(current_content)
            self.last_saved_content = current_content
            self.update_history_actions()
    
    def undo_input(self):
        content = self.input_history.undo()
        if content is not None:
            self.input_history.set_restoring(True)
            self.input_text.setPlainText(content)
            self.last_saved_content = content
            self.input_history.set_restoring(False)
            self.update_history_actions()
            self.show_status_message("已撤销")
    
    def redo_input(self):
        content = self.input_history.redo()
        if content is not None:
            self.input_history.set_restoring(True)
            self.input_text.setPlainText(content)
            self.last_saved_content = content
            self.input_history.set_restoring(False)
            self.update_history_actions()
            self.show_status_message("已重做")
    
    def update_history_actions(self):
        if self.main_window:
            self.main_window.undo_action.setEnabled(self.input_history.can_undo())
            self.main_window.redo_action.setEnabled(self.input_history.can_redo())
    
    def paste_input(self):
        clipboard = QApplication.clipboard()
        text = clipboard.text()
        if text:
            self.input_text.setPlainText(text)
            self.show_status_message("已粘贴")

    def open_text_tools_dialog(self):
        dialog = TextToolsDialog(self, self.input_text.toPlainText())
        if dialog.exec_() == dialog.Accepted:
            self.input_text.setPlainText(dialog.result_text())
            self.show_status_message("已应用文本工具结果")
    
    def clear_all(self):
        self.input_text.clear()
        self.output_text.clear()
        self.show_status_message("已清空")
    
    def to_upper(self):
        current_text = self.input_text.toPlainText()
        if current_text:
            self.input_history.push(current_text)
            self.last_saved_content = current_text
            self.update_history_actions()
        self.input_text.setPlainText(current_text.upper())
    
    def to_lower(self):
        current_text = self.input_text.toPlainText()
        if current_text:
            self.input_history.push(current_text)
            self.last_saved_content = current_text
            self.update_history_actions()
        self.input_text.setPlainText(current_text.lower())
    
    def strip_text(self):
        current_text = self.input_text.toPlainText()
        if current_text:
            self.input_history.push(current_text)
            self.last_saved_content = current_text
            self.update_history_actions()
        self.input_text.setPlainText(current_text.strip())
    
    def remove_spaces(self):
        current_text = self.input_text.toPlainText()
        if current_text:
            self.input_history.push(current_text)
            self.last_saved_content = current_text
            self.update_history_actions()
        self.input_text.setPlainText(current_text.replace(' ', ''))
    
    def remove_lines(self):
        current_text = self.input_text.toPlainText()
        if current_text:
            self.input_history.push(current_text)
            self.last_saved_content = current_text
            self.update_history_actions()
        self.input_text.setPlainText(current_text.replace('\n', '').replace('\r', ''))
    
    def reverse_text(self):
        current_text = self.input_text.toPlainText()
        if current_text:
            self.input_history.push(current_text)
            self.last_saved_content = current_text
            self.update_history_actions()
        self.input_text.setPlainText(current_text[::-1])
    
    def load_all_modules(self):
        """加载所有算法，委托给 CryptoLoader"""
        self.encrypt_modules.clear()
        self.decrypt_modules.clear()
        
        stats = self.crypto_loader.load_all_modules()
        
        # 从 CryptoLoader 提取模块对象（保持与原接口兼容）
        for name, info in self.crypto_loader.encrypt_modules.items():
            self.encrypt_modules[name] = info['module']
        for name, info in self.crypto_loader.decrypt_modules.items():
            self.decrypt_modules[name] = info['module']
        
        self.show_status_message(f"已加载 {len(self.encrypt_modules)} 个加密算法, {len(self.decrypt_modules)} 个解密算法")
    
    def select_encrypt_algo(self, algo_name):
        if self.panel_mode == 'decrypt':
            return
        self.current_mode = 'encrypt'
        self.current_algo_name = algo_name
        self.current_module = self.encrypt_modules.get(algo_name)
        self.show_status_message(f"已选择加密算法: {algo_name}")
        self.build_param_panel()
        self.auto_execute()
    
    def select_decrypt_algo(self, algo_name):
        if self.panel_mode == 'encrypt':
            return
        self.current_mode = 'decrypt'
        self.current_algo_name = algo_name
        self.current_module = self.decrypt_modules.get(algo_name)
        self.show_status_message(f"已选择解密算法: {algo_name}")
        self.build_param_panel()
        self.auto_execute()
    
    def build_param_panel(self):
        import inspect
        
        while self.param_layout.count():
            item = self.param_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.setParent(None)
                widget.deleteLater()
        
        self.param_widgets = {}
        
        if not self.current_module:
            self.param_widget.hide()
            return
        
        func_name = 'encrypt' if self.current_mode == 'encrypt' else 'decrypt'
        if not hasattr(self.current_module, func_name):
            self.param_widget.hide()
            return
        
        func = getattr(self.current_module, func_name)
        sig = inspect.signature(func)
        
        exclude_params = ['plaintext', 'ciphertext', 'cryptotext', 'text', 'input_text', 'message', 'msg']
        
        params_found = []
        for param_name, param in sig.parameters.items():
            if param_name.lower() in [p.lower() for p in exclude_params]:
                continue
            if param_name in ['self', 'cls', 'args', 'kwargs']:
                continue
            params_found.append((param_name, param))
        
        if not params_found:
            self.param_widget.hide()
            return
        
        self.param_label = QLabel(self.current_algo_name)
        self.param_label.setStyleSheet("font-weight: bold; font-size: 11pt;")
        self.param_layout.addWidget(self.param_label)

        import_params_btn = QPushButton("导入参数")
        import_params_btn.setToolTip("支持 JSON 或 key=value/key: value 文本；content/input/text 会导入内容区")
        import_params_btn.clicked.connect(self.import_params_file)
        self.param_layout.addWidget(import_params_btn)
        
        for param_name, param in params_found:
            label = QLabel(f"{param_name}:")
            self.param_layout.addWidget(label)
            
            control = self.create_param_control_from_signature(param_name, param)
            self.param_layout.addWidget(control)
            
            self.param_widgets[param_name] = {
                'control': control,
                'param_name': param_name,
                'param': param
            }
        
        self.param_layout.addStretch()
        self.param_widget.show()

    def import_input_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "导入内容文件", "", "All Files (*)")
        if not file_path:
            return
        self._load_input_from_file(file_path)

    def import_params_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "导入参数文件", "", "JSON/Text Files (*.json *.txt);;All Files (*)")
        if not file_path:
            return
        try:
            content, mode = self._read_file_as_panel_text(file_path, prefer_text=True)
        except Exception as ex:
            QMessageBox.warning(self, "导入失败", f"读取文件失败: {str(ex)}")
            return

        params = self._parse_imported_params(content)
        filled = self._apply_imported_params(params)
        if filled:
            self.show_status_message(f"已导入参数: {', '.join(filled)} ({mode})")
            self.auto_execute()
        else:
            QMessageBox.information(self, "导入参数", "未识别到当前算法参数。支持 JSON、key=value、key: value；content/input/text 会填入内容区。")

    def _read_file_as_panel_text(self, file_path, prefer_text=False):
        file_path = self._normalize_file_reference(file_path) or file_path
        path = Path(file_path)
        data = path.read_bytes()
        text_suffixes = {'.txt', '.json', '.csv', '.xml', '.html', '.htm', '.md', '.pem', '.key', '.pub', '.asc', '.log', '.ini', '.cfg'}
        should_try_text = prefer_text or path.suffix.lower() in text_suffixes
        if should_try_text:
            for encoding in ('utf-8-sig', 'utf-8', 'gb18030'):
                try:
                    text = data.decode(encoding)
                    if self._looks_like_text(text):
                        return text, encoding
                except UnicodeDecodeError:
                    pass
        if path.suffix and not should_try_text:
            for encoding in ('utf-8-sig', 'utf-8'):
                try:
                    text = data.decode(encoding)
                    if self._looks_like_text(text):
                        return text, encoding
                except UnicodeDecodeError:
                    pass
        return data.hex(), 'hex'

    def _normalize_file_reference(self, value):
        text = str(value).strip().strip('"\'')
        if not text:
            return None
        if text.lower().startswith('file://'):
            parsed = urlparse(text)
            path_text = unquote(parsed.path or '')
            if parsed.netloc:
                path_text = f"//{parsed.netloc}{path_text}"
            if re.match(r'^/[A-Za-z]:/', path_text):
                path_text = path_text[1:]
            return path_text.replace('/', '\\')
        return text

    def _load_input_from_file(self, file_path):
        try:
            normalized = self._normalize_file_reference(file_path) or file_path
            content, mode = self._read_file_as_panel_text(normalized)
        except Exception as ex:
            QMessageBox.warning(self, "导入失败", f"读取文件失败: {str(ex)}")
            return False
        self._loading_file_reference = True
        try:
            self.input_text.setPlainText(content)
        finally:
            self._loading_file_reference = False
        self.history_timer.start(500)
        self.auto_execute_timer.start(300)
        self.update_cursor_status()
        self.show_status_message(f"已导入内容: {normalized} ({mode})")
        return True

    def _replace_file_reference_input(self):
        text = self.input_text.toPlainText().strip()
        if not text or '\n' in text or '\r' in text:
            return False
        path_text = self._normalize_file_reference(text)
        if not path_text:
            return False
        try:
            if not Path(path_text).is_file():
                return False
        except OSError:
            return False
        return self._load_input_from_file(path_text)

    def _looks_like_text(self, text):
        if not text:
            return True
        sample = text[:4096]
        bad = sum(1 for ch in sample if ch == '\x00' or (ord(ch) < 32 and ch not in '\r\n\t'))
        return bad / max(1, len(sample)) < 0.02

    def _parse_imported_params(self, content):
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                return {str(k).strip(): str(v) for k, v in data.items() if v is not None}
        except Exception:
            pass

        params = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(('#', '//', ';')):
                continue
            match = re.match(r'^([A-Za-z_][\w.-]*)\s*(?:=|:)\s*(.+)$', line)
            if match:
                params[match.group(1).strip()] = match.group(2).strip().strip('"\'')
        return params

    def _apply_imported_params(self, params):
        filled = []
        input_keys = {'content', 'input', 'text', 'plaintext', 'ciphertext', 'cryptotext', 'message', 'msg'}
        lower_params = {key.lower(): value for key, value in params.items()}
        for key in input_keys:
            if key in lower_params:
                self.input_text.setPlainText(lower_params[key])
                filled.append('内容')
                break
        for name, info in self.param_widgets.items():
            value = lower_params.get(name.lower())
            if value is None:
                continue
            control = info['control']
            if isinstance(control, QCheckBox):
                control.setChecked(str(value).lower() in ('1', 'true', 'yes', 'on', '是'))
            elif isinstance(control, QSpinBox):
                try:
                    control.setValue(int(value))
                except ValueError:
                    continue
            elif isinstance(control, QLineEdit):
                control.setText(str(value))
            filled.append(name)
        return filled
    
    def create_param_control_from_signature(self, param_name, param):
        import inspect
        
        has_default = param.default != inspect.Parameter.empty
        default_value = param.default if has_default else None
        
        if default_value is not None and isinstance(default_value, bool):
            control = QCheckBox()
            control.setChecked(default_value)
            control.stateChanged.connect(lambda: self.auto_execute_timer.start(300))
        elif default_value is not None and isinstance(default_value, int):
            control = QSpinBox()
            control.setRange(-10000, 10000)
            control.setValue(default_value)
            control.valueChanged.connect(lambda: self.auto_execute_timer.start(300))
        elif default_value is not None and isinstance(default_value, float):
            control = QLineEdit()
            control.setText(str(default_value))
            control.textChanged.connect(lambda: self.auto_execute_timer.start(300))
        else:
            control = QLineEdit()
            if has_default and default_value is not None:
                control.setPlaceholderText(str(default_value))
            control.textChanged.connect(lambda: self.auto_execute_timer.start(300))
        
        return control
    
    def get_param_values(self):
        import inspect
        values = {}
        
        for name, info in self.param_widgets.items():
            control = info['control']
            param = info['param']
            
            has_default = param.default != inspect.Parameter.empty
            default_value = param.default if has_default else None
            
            if isinstance(control, QCheckBox):
                values[name] = control.isChecked()
            elif isinstance(control, QSpinBox):
                values[name] = control.value()
            elif isinstance(control, QLineEdit):
                text = control.text().strip()
                if text:
                    if default_value is not None and isinstance(default_value, int):
                        try:
                            values[name] = int(text)
                        except ValueError:
                            values[name] = text
                    elif default_value is not None and isinstance(default_value, float):
                        try:
                            values[name] = float(text)
                        except ValueError:
                            values[name] = text
                    else:
                        values[name] = text
                elif has_default:
                    values[name] = default_value
            
        return values
    
    def auto_execute(self):
        if not self.current_module:
            return
        
        input_text = self.input_text.toPlainText()
        if not input_text:
            self.output_text.clear()
            return
        
        params = self.get_param_values()
        
        try:
            if self.current_mode == 'encrypt':
                func = getattr(self.current_module, 'encrypt', None)
            else:
                func = getattr(self.current_module, 'decrypt_with_params', None)
                if not func:
                    func = getattr(self.current_module, 'decrypt', None)
            
            if func:
                result = func(input_text, **params)
                self.set_output_with_highlight(str(result))
                
                if self.auto_copy:
                    copy_plain_text(str(result))
                
                if self.auto_swap:
                    self.swap_io()
                
                self.show_status_message(f"{'加密' if self.current_mode == 'encrypt' else '解密'}完成")
        except Exception as e:
            self.set_output_with_highlight(f"错误: {str(e)}")
    
    def one_click_decrypt(self):
        input_text = self.input_text.toPlainText()
        if not input_text:
            self.show_status_message("请先输入内容")
            return
        patterns = [p.strip() for p in self.match_pattern.split(';') if p.strip()]
        results = []
        for item in self.crypto_loader.try_decrypt_all(input_text, match_patterns=patterns):
            suffix = f" / {item['params']}" if item.get('params') else ""
            title = f"【{item['name']} - 爆破结果{suffix}】" if item.get('is_brute') else f"【{item['name']}】"
            results.append(f"{title}\n{item['result']}")
        results = self._sort_result_blocks_by_score(results)
        
        if results:
            self.set_output_with_highlight('\n\n'.join(results))
        else:
            self.set_output_with_highlight("未能解密")
        
        self.show_status_message(f"已尝试 {len(self.decrypt_modules)} 种解密算法")
    
    def start_recursive_decrypt(self):
        input_text = self.input_text.toPlainText()
        if not input_text:
            self.show_status_message("请先输入内容")
            return
        
        patterns = [p.strip() for p in self.match_pattern.split(';') if p.strip()]
        if not patterns:
            patterns = ['flag', 'ctf', 'key']
        
        self.recursive_decrypt_btn.setEnabled(False)
        self.recursive_decrypt_btn.setText("解密中...")
        self.show_status_message("正在进行递归解密...")
        
        if self.async_decryptor is None:
            self.async_decryptor = AsyncRecursiveDecryptor(
                self.decrypt_modules,
                self.recursive_max_depth,
                max_workers=self.recursive_max_workers,
                max_tasks=self.recursive_max_tasks,
                brute_force_small_keyspaces=self.recursive_bruteforce,
            )
            self.async_decryptor.finished.connect(self.on_recursive_decrypt_finished)
            self.async_decryptor.progress.connect(self.on_recursive_decrypt_progress)
            self.async_decryptor.match_found.connect(self.on_recursive_match_found)
        
        self.async_decryptor.start(input_text, patterns, self.case_sensitive)
    
    def on_recursive_decrypt_progress(self, msg: str):
        self.show_status_message(msg)
    
    def on_recursive_match_found(self, match_result: dict):
        pass
    
    def on_recursive_decrypt_finished(self, result: dict):
        self.recursive_decrypt_btn.setEnabled(True)
        self.recursive_decrypt_btn.setText("递归解密")
        
        matched_results = result.get('matched_results', [])
        all_results = result.get('all_results', [])
        stats = result.get('stats', {})
        stats_line = (
            f"统计: 任务 {stats.get('processed_tasks', 0)}/{stats.get('max_tasks', self.recursive_max_tasks)}, "
            f"尝试 {stats.get('attempts', 0)} 次, 候选 {stats.get('candidates', len(all_results))} 个, "
            f"队列剩余 {stats.get('queued_tasks', 0)}"
        )
        finish_reason = stats.get('finish_reason', '')
        
        if matched_results:
            seen_texts = set()
            unique_matches = []
            for match in matched_results:
                text_hash = hash(match['text'][:200])
                if text_hash not in seen_texts:
                    seen_texts.add(text_hash)
                    unique_matches.append(match)
            
            output_parts = []
            output_parts.append(f"找到 {len(unique_matches)} 个匹配项:\n")
            output_parts.append(stats_line)
            if finish_reason:
                output_parts.append(f"结束原因: {finish_reason}")
            
            unique_matches.sort(key=lambda item: (feature_score(item.get('features') or []), item.get('depth', 0)), reverse=True)
            display_limit = max(1, min(int(getattr(self, 'recursive_max_display_results', 100)), 1000))
            shown_matches = unique_matches[:display_limit]
            if len(unique_matches) > display_limit:
                output_parts.append(f"仅显示特征值最高的 {display_limit} 条，剩余 {len(unique_matches) - display_limit} 条已隐藏")

            for i, match in enumerate(shown_matches, 1):
                output_parts.append(f"\n--- 匹配结果 #{i} ---")
                output_parts.append(f"匹配关键词: {', '.join(match['matched_patterns'])}")
                output_parts.append(f"解密深度: {match['depth']}")
                features = match.get('features') or []
                if features:
                    output_parts.append(f"结果特征: {', '.join(features)}")
                
                if match['path']:
                    output_parts.append("解密路径:")
                    for j, step in enumerate(match['path'], 1):
                        params = f" ({step.get('params')})" if step.get('params') else ""
                        output_parts.append(f"  {j}. {step['algorithm']}{params}" + 
                                          (" (爆破)" if step.get('is_brute') else ""))
                
                output_parts.append(f"\n解密结果:\n{match['text']}")
                output_parts.append("")
            
            self.set_output_with_highlight('\n'.join(output_parts))
            self.show_status_message(
                f"递归解密完成: 尝试 {stats.get('attempts', 0)} 次, 找到 {len(unique_matches)} 个匹配项"
            )
        else:
            output_parts = []
            output_parts.append("多层解密中无匹配项\n")
            output_parts.append(stats_line)
            if finish_reason:
                output_parts.append(f"结束原因: {finish_reason}")
            
            if all_results:
                output_parts.append("【已尝试的解密方法】")
                
                seen_results = set()
                display_limit = max(1, min(int(getattr(self, 'recursive_max_display_results', 100)), 1000))
                sorted_results = sorted(
                    all_results,
                    key=lambda item: feature_score(item.get('features') or []),
                    reverse=True,
                )
                shown_count = 0
                for r in sorted_results:
                    if shown_count >= display_limit:
                        break
                    result_hash = hash(r['result'][:100])
                    if result_hash not in seen_results:
                        seen_results.add(result_hash)
                        shown_count += 1
                        output_parts.append(f"\n【{r['algorithm']}】" + 
                                          (" (爆破)" if r.get('is_brute') else ""))
                        features = r.get('features') or []
                        if features:
                            output_parts.append(f"特征: {', '.join(features)}")
                        preview = r['result'][:200] if len(r['result']) > 200 else r['result']
                        output_parts.append(preview)
                hidden_count = max(0, len(all_results) - shown_count)
                if hidden_count:
                    output_parts.append(f"\n仅显示特征值最高的 {shown_count} 条，剩余结果已隐藏")
            else:
                output_parts.append("\n所有解密算法均未能解密此内容")
            
            self.set_output_with_highlight('\n'.join(output_parts))
            self.show_status_message(f"递归解密完成: 尝试 {stats.get('attempts', 0)} 次，无匹配项")
    
    def swap_io(self):
        output_text = self.output_text.toPlainText()
        self.input_text.setPlainText(output_text)
        self.show_status_message("已将输出内容移至输入框")
    
    def copy_output(self):
        text = self.output_text.toPlainText()
        if text:
            copy_plain_text(text)
            self.show_status_message("已复制到剪贴板")
        else:
            self.show_status_message("输出框为空")
    
    def apply_colors(self):
        self.input_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: {self.input_bg_color};
                border: none;
            }}
        """)
        
        self.output_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: {self.output_bg_color};
                border: none;
            }}
        """)
    
    def eventFilter(self, obj, event):
        if obj == self.input_text:
            if event.type() == QEvent.DragEnter and event.mimeData().hasUrls():
                event.acceptProposedAction()
                return True
            if event.type() == QEvent.Drop and event.mimeData().hasUrls():
                urls = event.mimeData().urls()
                file_path = urls[0].toLocalFile() if urls else ''
                if file_path and self._load_input_from_file(file_path):
                    event.acceptProposedAction()
                    return True
        if obj == self.input_text and event.type() == event.KeyPress:
            if event.modifiers() == Qt.ControlModifier:
                if event.key() == Qt.Key_Z:
                    self.undo_input()
                    return True
                elif event.key() == Qt.Key_Y:
                    self.redo_input()
                    return True
        return super().eventFilter(obj, event)
    
    def toggle_quick_tag(self, tag):
        self.update_match_from_tags()
    
    def clear_all_tags(self):
        for tag, btn in self.tag_buttons.items():
            btn.setChecked(False)
        self.match_input.clear()
    
    def update_match_from_tags(self):
        current_patterns = [p.strip() for p in self.match_input.text().split(';') if p.strip()]
        
        current_patterns = [p for p in current_patterns if p.lower() not in [t.lower() for t in self.quick_tags]]
        
        selected_tags = [tag for tag, btn in self.tag_buttons.items() if btn.isChecked()]
        
        all_patterns = current_patterns + selected_tags
        
        new_text = ';'.join(all_patterns)
        
        self.match_input.blockSignals(True)
        self.match_input.setText(new_text)
        self.match_input.blockSignals(False)
        
        self.match_pattern = new_text
        self.highlight_matches()
    
    def on_match_pattern_changed(self, pattern):
        self.match_pattern = pattern
        
        current_patterns = [p.strip().lower() for p in pattern.split(';') if p.strip()]
        
        for tag, btn in self.tag_buttons.items():
            btn.blockSignals(True)
            btn.setChecked(tag.lower() in current_patterns)
            btn.blockSignals(False)
        
        self.highlight_matches()
    
    def on_case_sensitive_changed(self, state):
        self.case_sensitive = (state == Qt.Checked)
        self.highlight_matches()
        self._update_search_positions()
        self._update_highlighter_patterns()
    
    def highlight_matches(self):
        if not self.match_pattern:
            self.match_count_label.setText("")
            self.match_positions = []
            self._match_highlighter_patterns = []
            self._update_highlighter_patterns()
            return
        
        text = self.last_output_text if self.last_output_text else self.output_text.toPlainText()
        if not text:
            return
            
        patterns = [p.strip() for p in self.match_pattern.split(';') if p.strip()]
        
        if not patterns:
            self.match_count_label.setText("")
            self.match_positions = []
            self._match_highlighter_patterns = []
            self._update_highlighter_patterns()
            return
        
        highlight_colors = [
            ("#FFFF00", "#FF0000"),
            ("#00FFFF", "#0000FF"),
            ("#00FF00", "#006600"),
            ("#FF00FF", "#990099"),
            ("#FFA500", "#CC5500"),
            ("#FFC0CB", "#FF1493"),
            ("#87CEEB", "#000080"),
            ("#98FB98", "#006400"),
        ]
        
        highlighter_patterns = []
        all_matches = []
        
        for pattern_idx, pattern in enumerate(patterns):
            color_idx = pattern_idx % len(highlight_colors)
            bg_color, fg_color = highlight_colors[color_idx]
            
            highlighter_patterns.append({
                'pattern': pattern,
                'bg_color': bg_color,
                'fg_color': fg_color
            })
            
            search_text = text
            search_pattern = pattern
            if not self.case_sensitive:
                search_text = text.lower()
                search_pattern = pattern.lower()
            
            start = 0
            while True:
                pos = search_text.find(search_pattern, start)
                if pos == -1:
                    break
                
                all_matches.append({
                    'pos': pos,
                    'length': len(pattern),
                    'pattern': pattern,
                    'pattern_idx': pattern_idx,
                    'bg_color': bg_color,
                    'fg_color': fg_color
                })
                start = pos + 1
        
        all_matches.sort(key=lambda x: (x['pattern_idx'], x['pos']))
        
        if not all_matches:
            self.match_count_label.setText("无匹配")
            self.match_positions = []
        else:
            self.match_count_label.setText(f"{len(all_matches)} 个匹配")
            self.current_match_index = 0
            self.match_positions = all_matches
        
        self._match_highlighter_patterns = highlighter_patterns
        self._update_highlighter_patterns()
        self._scroll_to_match(0, set_focus=False)

    def _sort_result_blocks_by_keyword(self, result_blocks):
        """Move result blocks containing match keywords to the top."""
        patterns = [p.strip() for p in self.match_pattern.split(';') if p.strip()]
        if not patterns or len(result_blocks) < 2:
            return result_blocks
        
        matched_blocks = []
        other_blocks = []
        for block in result_blocks:
            search_block = block if self.case_sensitive else block.lower()
            matched = False
            for pattern in patterns:
                search_pattern = pattern if self.case_sensitive else pattern.lower()
                if search_pattern and search_pattern in search_block:
                    matched = True
                    break
            if matched:
                matched_blocks.append(block)
            else:
                other_blocks.append(block)
        
        if not matched_blocks:
            return result_blocks
        
        sorted_blocks = ["【匹配关键字结果（置顶）】"] + matched_blocks
        if other_blocks:
            sorted_blocks.append("【其他结果】")
            sorted_blocks.extend(other_blocks)
        return sorted_blocks
    
    def _sort_result_blocks_by_score(self, result_blocks):
        """Sort one-click decrypt results by likely usefulness."""
        if len(result_blocks) < 2:
            return result_blocks
        
        scored = [(self._score_result_block(block), idx, block) for idx, block in enumerate(result_blocks)]
        scored.sort(key=lambda item: (-item[0], item[1]))
        sorted_blocks = [block for _, _, block in scored]
        
        top_score = scored[0][0]
        if top_score <= 0:
            return result_blocks
        
        top_blocks = [block for score, _, block in scored if score > 0]
        other_blocks = [block for score, _, block in scored if score <= 0]
        output = ["【高可信结果（置顶）】"] + top_blocks
        if other_blocks:
            output.append("【其他结果】")
            output.extend(other_blocks)
        return output
    
    def _score_result_block(self, block):
        score = 0
        text = block if self.case_sensitive else block.lower()
        patterns = [p.strip() for p in self.match_pattern.split(';') if p.strip()]
        for pattern in patterns:
            search_pattern = pattern if self.case_sensitive else pattern.lower()
            if search_pattern and search_pattern in text:
                score += 50
        
        if re.search(r"flag\s*\{[^}]{3,}\}", block, re.IGNORECASE):
            score += 120
        if re.search(r"ctf\s*\{[^}]{3,}\}", block, re.IGNORECASE):
            score += 100
        if "{" in block and "}" in block:
            score += 15
        
        result_part = block.split('\n', 1)[1] if '\n' in block else block
        if result_part:
            printable = sum(1 for ch in result_part if ch.isprintable() or ch in '\r\n\t')
            ratio = printable / max(1, len(result_part))
            if ratio > 0.92:
                score += 20
            if 4 <= len(result_part.strip()) <= 300:
                score += 10
            if result_part.strip().isascii():
                score += 5
        
        bad_markers = ("错误", "失败", "解码错误", "???")
        if any(marker in block for marker in bad_markers):
            score -= 80
        return score
    
    def find_prev_match(self):
        if not hasattr(self, 'match_positions') or not self.match_positions:
            return
        
        if not hasattr(self, 'current_match_index'):
            self.current_match_index = 0
        
        self.current_match_index -= 1
        if self.current_match_index < 0:
            self.current_match_index = len(self.match_positions) - 1
        
        self._scroll_to_match(self.current_match_index, set_focus=True)
    
    def find_next_match(self):
        if not hasattr(self, 'match_positions') or not self.match_positions:
            return
        
        if not hasattr(self, 'current_match_index'):
            self.current_match_index = 0
        
        self.current_match_index += 1
        if self.current_match_index >= len(self.match_positions):
            self.current_match_index = 0
        
        self._scroll_to_match(self.current_match_index, set_focus=True)
    
    def _scroll_to_match(self, index, set_focus=False):
        if not hasattr(self, 'match_positions') or not self.match_positions:
            return
        
        if index < 0 or index >= len(self.match_positions):
            return
        
        match = self.match_positions[index]
        pos = match['pos']
        length = match['length']
        
        cursor = QTextCursor(self.output_text.document())
        cursor.setPosition(pos)
        cursor.setPosition(pos + length, QTextCursor.KeepAnchor)
        
        self.output_text.setTextCursor(cursor)
        if set_focus:
            self.output_text.setFocus()
        self.output_text.ensureCursorVisible()
        
        self.match_count_label.setText(f"{index + 1}/{len(self.match_positions)} 个匹配")

    def on_output_search_changed(self, text):
        self._update_search_positions(text)
        self._update_highlighter_patterns()
    
    def _update_search_positions(self, query=None):
        query = self.output_search_input.text().strip() if query is None else query.strip()
        text = self.output_text.toPlainText()
        self.search_positions = []
        self.current_search_index = -1
        
        if not query or not text:
            self.output_search_count_label.setText("")
            return
        
        search_text = text if self.case_sensitive else text.lower()
        search_query = query if self.case_sensitive else query.lower()
        start = 0
        while True:
            pos = search_text.find(search_query, start)
            if pos == -1:
                break
            self.search_positions.append({'pos': pos, 'length': len(query)})
            start = pos + 1
        
        if self.search_positions:
            self.output_search_count_label.setText(f"{len(self.search_positions)} 个结果")
        else:
            self.output_search_count_label.setText("无结果")
    
    def find_prev_search_result(self):
        if not self.search_positions:
            return
        self.current_search_index -= 1
        if self.current_search_index < 0:
            self.current_search_index = len(self.search_positions) - 1
        self._scroll_to_search_result(self.current_search_index)
    
    def find_next_search_result(self):
        if not self.search_positions:
            return
        self.current_search_index += 1
        if self.current_search_index >= len(self.search_positions):
            self.current_search_index = 0
        self._scroll_to_search_result(self.current_search_index)
    
    def _scroll_to_search_result(self, index):
        if index < 0 or index >= len(self.search_positions):
            return
        match = self.search_positions[index]
        cursor = QTextCursor(self.output_text.document())
        cursor.setPosition(match['pos'])
        cursor.setPosition(match['pos'] + match['length'], QTextCursor.KeepAnchor)
        self.output_text.setTextCursor(cursor)
        self.output_text.setFocus()
        self.output_text.ensureCursorVisible()
        self.output_search_count_label.setText(f"{index + 1}/{len(self.search_positions)} 个结果")
    
    def _update_highlighter_patterns(self):
        patterns = list(getattr(self, '_match_highlighter_patterns', []))
        search_text = self.output_search_input.text().strip() if hasattr(self, 'output_search_input') else ''
        if search_text:
            patterns.append({
                'pattern': search_text,
                'bg_color': '#111111',
                'fg_color': '#FFFFFF',
            })
        self.highlighter.set_patterns(patterns, self.case_sensitive)
    
    def set_output_with_highlight(self, text):
        self.last_output_text = text
        self.output_text.setPlainText(text)
        if self.match_pattern:
            self.highlight_matches()
        else:
            self._update_highlighter_patterns()
        self._update_search_positions()
        self.input_text.setFocus()
    
    def show_decrypt_records(self):
        records = self.record_manager.get_records()
        if not records:
            QMessageBox.information(self, "解密记录", "暂无解密记录")
            return
        
        record_dialog = DecryptRecordsDialog(self, records)
        record_dialog.exec_()
    
    def clear_decrypt_records(self):
        reply = QMessageBox.question(
            self, "确认清空",
            "确定要清空所有解密记录吗？",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.record_manager.clear_records()
            self.show_status_message("已清空解密记录")


class DecryptRecordsDialog(QDialog):
    """解密记录对话框"""
    
    def __init__(self, parent, records):
        super().__init__(parent)
        self.records = records
        self.setWindowTitle("解密记录")
        self.resize(800, 600)
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        self.record_list = QListWidget()
        self.record_list.currentRowChanged.connect(self.show_record_detail)
        layout.addWidget(QLabel("记录列表:"), 0)
        layout.addWidget(self.record_list, 1)
        
        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setFont(QFont("Consolas", 10))
        layout.addWidget(QLabel("详细信息:"), 0)
        layout.addWidget(self.detail_text, 2)
        
        btn_layout = QHBoxLayout()
        
        export_btn = QPushButton("导出记录")
        export_btn.clicked.connect(self.export_records)
        btn_layout.addWidget(export_btn)
        
        close_btn = QPushButton("关闭")
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)
        
        layout.addLayout(btn_layout)
        
        self.load_records()
    
    def load_records(self):
        for record in self.records:
            item_text = f"[{record.timestamp[:19]}] {', '.join(record.matched_patterns)} - {record.final_result[:50]}..."
            self.record_list.addItem(item_text)
    
    def show_record_detail(self, row):
        if 0 <= row < len(self.records):
            record = self.records[row]
            
            detail = []
            detail.append(f"时间: {record.timestamp}")
            detail.append(f"匹配关键词: {', '.join(record.matched_patterns)}")
            detail.append("")
            detail.append("=" * 50)
            detail.append("原始文本:")
            detail.append("=" * 50)
            detail.append(record.original_text[:500])
            detail.append("")
            detail.append("=" * 50)
            detail.append("解密结果:")
            detail.append("=" * 50)
            detail.append(record.final_result)
            detail.append("")
            detail.append("=" * 50)
            detail.append("解密路径:")
            detail.append("=" * 50)
            for i, step in enumerate(record.decrypt_path, 1):
                detail.append(f"{i}. {step.get('algorithm', 'Unknown')}" + 
                            (" (爆破)" if step.get('is_brute') else ""))
            
            self.detail_text.setPlainText('\n'.join(detail))
    
    def export_records(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, "导出记录", "", "JSON Files (*.json);;Text Files (*.txt)"
        )
        
        if file_path:
            try:
                if file_path.endswith('.json'):
                    data = [r.to_dict() for r in self.records]
                    with open(file_path, 'w', encoding='utf-8') as f:
                        json.dump(data, f, ensure_ascii=False, indent=2)
                else:
                    lines = []
                    for record in self.records:
                        lines.append(f"时间: {record.timestamp}")
                        lines.append(f"匹配关键词: {', '.join(record.matched_patterns)}")
                        lines.append(f"原始文本: {record.original_text[:200]}")
                        lines.append(f"解密结果: {record.final_result}")
                        lines.append("-" * 50)
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write('\n'.join(lines))
                
                QMessageBox.information(self, "导出成功", f"已导出到: {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "导出失败", f"导出失败: {str(e)}")
