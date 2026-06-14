"""
LCG工具对话框模块
=================
提供线性同余生成器(LCG)攻击的图形界面
"""

from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QTextEdit, QGroupBox, 
                             QComboBox, QWidget, QSplitter, QLineEdit,
                             QApplication)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject

from algorithms.asymmetric.lcg.attacks.loader import LCGLoader
from .clipboard_utils import copy_plain_text, install_plain_text_copy
from .file_drop_helper import TextFileDropHelper


class LCGAttackWorker(QObject):
    """LCG攻击工作线程"""
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    
    def __init__(self, loader, attack_name, params):
        super().__init__()
        self.loader = loader
        self.attack_name = attack_name
        self.params = params
    
    def run(self):
        try:
            result = self.loader.execute_attack(self.attack_name, **self.params)
            self.finished.emit(result)
        except Exception as ex:
            self.error.emit(str(ex))


class LCGDialog(QDialog):
    """LCG工具对话框"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("LCG工具")
        self.setMinimumSize(900, 600)
        self.resize(1000, 650)

        self.attack_loader = LCGLoader()
        self.attack_loader.load_all_attacks()
        
        self.attack_thread = None
        self.attack_worker = None
        
        self.setup_ui()
        install_plain_text_copy(self)
        self.outputs_drop_helper = TextFileDropHelper(self, self.outputs_edit)
    
    def setup_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setSpacing(5)
        main_layout.setContentsMargins(8, 8, 8, 8)
        
        splitter = QSplitter(Qt.Horizontal)
        
        left_widget = QWidget()
        left_layout = QVBoxLayout()
        left_layout.setSpacing(5)
        
        params_group = QGroupBox("参数输入")
        params_layout = QVBoxLayout()
        params_layout.setSpacing(4)
        
        params_layout.addWidget(QLabel("输出序列:"))
        self.outputs_edit = QTextEdit()
        self.outputs_edit.setMinimumHeight(80)
        self.outputs_edit.setPlaceholderText("输入LCG连续输出值，逗号或换行分隔")
        params_layout.addWidget(self.outputs_edit)
        
        param_row = QHBoxLayout()
        param_row.addWidget(QLabel("模数m:"))
        self.m_edit = QLineEdit()
        self.m_edit.setPlaceholderText("可选，已知时填入")
        param_row.addWidget(self.m_edit)
        params_layout.addLayout(param_row)
        
        param_row2 = QHBoxLayout()
        param_row2.addWidget(QLabel("乘数a:"))
        self.a_edit = QLineEdit()
        self.a_edit.setPlaceholderText("可选")
        param_row2.addWidget(self.a_edit)
        param_row2.addWidget(QLabel("增量c:"))
        self.c_edit = QLineEdit()
        self.c_edit.setPlaceholderText("可选")
        param_row2.addWidget(self.c_edit)
        params_layout.addLayout(param_row2)
        
        params_group.setLayout(params_layout)
        left_layout.addWidget(params_group)
        
        attack_group = QGroupBox("攻击方式")
        attack_layout = QVBoxLayout()
        attack_layout.setSpacing(4)
        
        mode_row = QHBoxLayout()
        mode_row.addWidget(QLabel("选择:"))
        self.mode_combo = QComboBox()
        
        attack_names = self.attack_loader.get_attack_names()
        for name in attack_names:
            info = self.attack_loader.get_attack_info(name)
            desc = info.get('desc', '') if info else ''
            self.mode_combo.addItem(f"{name}", name)
        
        self.mode_combo.currentIndexChanged.connect(self._on_mode_changed)
        mode_row.addWidget(self.mode_combo)
        attack_layout.addLayout(mode_row)
        
        self.mode_hint_label = QLabel()
        self.mode_hint_label.setStyleSheet("color: #666;")
        self.mode_hint_label.setWordWrap(True)
        attack_layout.addWidget(self.mode_hint_label)
        
        btn_row = QHBoxLayout()
        self.attack_btn = QPushButton("执行攻击")
        self.attack_btn.clicked.connect(self._execute_attack)
        btn_row.addWidget(self.attack_btn)
        clear_btn = QPushButton("清空")
        clear_btn.clicked.connect(self._clear_result)
        btn_row.addWidget(clear_btn)
        attack_layout.addLayout(btn_row)
        
        attack_group.setLayout(attack_layout)
        left_layout.addWidget(attack_group)
        
        left_layout.addStretch()
        left_widget.setLayout(left_layout)
        
        right_widget = QWidget()
        right_layout = QVBoxLayout()
        right_layout.setSpacing(5)
        
        result_group = QGroupBox("结果")
        result_layout = QVBoxLayout()
        result_layout.setSpacing(4)
        
        result_layout.addWidget(QLabel("输出:"))
        self.result_edit = QTextEdit()
        self.result_edit.setReadOnly(True)
        self.result_edit.setStyleSheet("background-color: #f0f0f0;")
        result_layout.addWidget(self.result_edit)
        
        copy_row = QHBoxLayout()
        copy_btn = QPushButton("复制结果")
        copy_btn.clicked.connect(lambda: copy_plain_text(self.result_edit.toPlainText()))
        copy_row.addWidget(copy_btn)
        copy_row.addStretch()
        result_layout.addLayout(copy_row)
        
        result_group.setLayout(result_layout)
        right_layout.addWidget(result_group)
        
        right_layout.addStretch()
        right_widget.setLayout(right_layout)
        
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setSizes([400, 500])
        
        main_layout.addWidget(splitter)
        self.setLayout(main_layout)
        
        self._on_mode_changed(0)
    
    def _on_mode_changed(self, index):
        """攻击方式改变"""
        mode = self.mode_combo.currentData()
        info = self.attack_loader.get_attack_info(mode)
        if info and 'hint' in info:
            self.mode_hint_label.setText(info['hint'][:200])
        else:
            self.mode_hint_label.setText("")
    
    def _clear_result(self):
        """清空结果"""
        self.result_edit.clear()
    
    def _execute_attack(self):
        """执行攻击"""
        self._clear_result()
        
        mode = self.mode_combo.currentData()
        if not mode:
            self.result_edit.setPlainText("请选择攻击方式")
            return
        
        outputs = self.outputs_edit.toPlainText()
        m = self.m_edit.text()
        a = self.a_edit.text()
        c = self.c_edit.text()
        
        params = {
            'outputs': outputs,
            'm': m,
            'a': a,
            'c': c
        }
        
        self._start_attack(mode, params)
    
    def _start_attack(self, attack_name, params):
        """启动攻击线程"""
        if self.attack_thread is not None and self.attack_thread.isRunning():
            self.attack_thread.quit()
            self.attack_thread.wait(1000)
        
        self.attack_btn.setEnabled(False)
        self.result_edit.setPlainText(f"正在执行 {attack_name}...")
        
        self.attack_worker = LCGAttackWorker(self.attack_loader, attack_name, params)
        self.attack_thread = QThread()
        self.attack_worker.moveToThread(self.attack_thread)
        
        self.attack_thread.started.connect(self.attack_worker.run)
        self.attack_worker.finished.connect(self._on_attack_finished)
        self.attack_worker.error.connect(self._on_attack_error)
        
        self.attack_thread.start()
    
    def _on_attack_finished(self, result):
        """攻击完成"""
        self.attack_btn.setEnabled(True)
        
        if self.attack_thread is not None:
            self.attack_thread.quit()
            self.attack_thread.wait(1000)
            self.attack_thread = None
            self.attack_worker = None
        
        parsed = self.attack_loader.parse_attack_result(result)
        text = parsed.get('text', str(result))
        self.result_edit.setPlainText(text)
    
    def _on_attack_error(self, error_msg):
        """攻击错误"""
        self.attack_btn.setEnabled(True)
        
        if self.attack_thread is not None:
            self.attack_thread.quit()
            self.attack_thread.wait(1000)
            self.attack_thread = None
            self.attack_worker = None
        
        self.result_edit.setPlainText(f"攻击出错: {error_msg}")
    
    def closeEvent(self, event):
        """关闭事件"""
        if self.attack_thread is not None and self.attack_thread.isRunning():
            self.attack_thread.quit()
            self.attack_thread.wait(2000)
        event.accept()
