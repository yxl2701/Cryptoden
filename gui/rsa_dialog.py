"""
RSA加解密对话框模块
==================
提供RSA非对称加密的图形界面，支持加密、解密和攻击功能
"""

from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QTextEdit, QGroupBox, 
                             QFileDialog, QMessageBox, QComboBox, QSpinBox,
                             QTabWidget, QWidget, QGridLayout, QApplication,
                             QSplitter, QFrame, QLineEdit, QScrollArea)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject, QEvent
import math
import re
import ast

try:
    from Crypto.PublicKey import RSA
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

from algorithms.asymmetric.rsa.attacks.loader import RSALoader
from algorithms.asymmetric.rsa.utils import (
    extended_gcd, mod_inverse, is_prime, generate_prime,
    format_value, parse_input_value, decode_plaintext
)
from algorithms.asymmetric.rsa.rsa import derive_parameters
from .clipboard_utils import copy_plain_text, install_plain_text_copy


ATTACK_ALIASES = {
    'known_factor': '已知因子分解',
    'broadcast': '小指数广播攻击',
    'low_exponent': '低加密指数攻击',
    'wiener': 'Wiener攻击',
    'extended_wiener': '扩展Wiener攻击',
    'fermat': 'Fermat分解',
    'pollard_p1': 'Pollard p-1分解',
    'williams_p1': 'Williams p+1分解',
    'pollard_rho': 'PollardRho分解',
    'common_modulus': '共模攻击',
    'crt_fault': 'CRT故障攻击',
    'lsb_oracle': 'LSB Oracle攻击',
}


class RSAKeyGeneratorWorker(QObject):
    """RSA密钥生成工作线程"""
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    def __init__(self, key_size, prime_count, e):
        super().__init__()
        self.key_size = key_size
        self.prime_count = prime_count
        self.e = e
    
    def run(self):
        try:
            primes = []
            prime_size = self.key_size // self.prime_count
            for _ in range(self.prime_count):
                primes.append(generate_prime(prime_size))
            
            n = 1
            for p in primes:
                n *= p
            
            phi = 1
            for p in primes:
                phi *= (p - 1)
            
            d = mod_inverse(self.e, phi)
            
            if d is None:
                self.error.emit("无法计算私钥d")
                return
            
            result = {
                'n': n,
                'e': self.e,
                'd': d,
                'primes': primes
            }
            
            if len(primes) == 2 and CRYPTO_AVAILABLE:
                key = RSA.construct((n, self.e, d, primes[0], primes[1]))
                result['pub_key'] = key.publickey().export_key().decode()
                result['pri_key'] = key.export_key().decode()
            
            self.finished.emit(result)
        except Exception as ex:
            self.error.emit(str(ex))


class RSAAttackWorker(QObject):
    """RSA攻击工作线程"""
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    
    def __init__(self, loader, attack_name, params):
        super().__init__()
        self.loader = loader
        self.attack_name = attack_name
        self.params = params
        self.cancelled = False

    def cancel(self):
        self.cancelled = True
    
    def run(self):
        try:
            if self.cancelled:
                return
            result = self.loader.execute_attack(self.attack_name, **self.params)
            if self.cancelled:
                return
            self.finished.emit(result)
        except Exception as ex:
            if self.cancelled:
                return
            self.error.emit(str(ex))


class RSADialog(QDialog):
    """RSA加解密对话框"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("RSA工具")
        self.setMinimumSize(1200, 850)
        self.resize(1200, 850)

        self.attack_loader = RSALoader()
        self.attack_loader.load_all_attacks()
        
        self.current_key = None
        self.current_cipher = None
        self.current_result = None
        self.key_gen_thread = None
        self.key_gen_worker = None
        self.attack_thread = None
        self.attack_worker = None
        self.setAcceptDrops(True)
        
        self.setup_ui()
        self._install_file_drop_handlers()
        install_plain_text_copy(self)
    
    def setup_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setSpacing(5)
        main_layout.setContentsMargins(8, 8, 8, 8)
        
        tabs = QTabWidget()
        tabs.addTab(self._create_encrypt_tab(), "RSA加密")
        tabs.addTab(self._create_decrypt_tab(), "RSA解密/攻击")
        
        main_layout.addWidget(tabs)
        self.setLayout(main_layout)

    def _scroll_area(self, widget, min_width=0):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(widget)
        if min_width:
            scroll.setMinimumWidth(min_width)
        return scroll
    
    def _create_encrypt_tab(self):
        """创建加密标签页 - 左右分栏布局"""
        widget = QWidget()
        layout = QHBoxLayout()
        layout.setSpacing(8)
        
        splitter = QSplitter(Qt.Horizontal)
        
        left_widget = QWidget()
        left_layout = QVBoxLayout()
        left_layout.setSpacing(5)
        
        key_gen_group = QGroupBox("密钥生成")
        key_gen_layout = QGridLayout()
        key_gen_layout.setSpacing(5)
        
        key_gen_layout.addWidget(QLabel("密钥长度:"), 0, 0)
        self.key_size_spin = QSpinBox()
        self.key_size_spin.setRange(512, 4096)
        self.key_size_spin.setValue(2048)
        self.key_size_spin.setSingleStep(256)
        key_gen_layout.addWidget(self.key_size_spin, 0, 1)
        
        key_gen_layout.addWidget(QLabel("素数数量:"), 1, 0)
        self.prime_count_spin = QSpinBox()
        self.prime_count_spin.setRange(2, 8)
        self.prime_count_spin.setValue(2)
        key_gen_layout.addWidget(self.prime_count_spin, 1, 1)
        
        key_gen_layout.addWidget(QLabel("输出格式:"), 2, 0)
        self.key_format_combo = QComboBox()
        self.key_format_combo.addItem("十进制", "decimal")
        self.key_format_combo.addItem("十六进制", "hex")
        self.key_format_combo.addItem("Base64", "base64")
        self.key_format_combo.currentIndexChanged.connect(self._on_key_format_changed)
        key_gen_layout.addWidget(self.key_format_combo, 2, 1)
        
        btn_row = QHBoxLayout()
        self.gen_key_btn = QPushButton("生成密钥")
        self.gen_key_btn.clicked.connect(self._generate_key)
        btn_row.addWidget(self.gen_key_btn)
        clear_btn = QPushButton("清空")
        clear_btn.clicked.connect(self._clear_key_fields)
        btn_row.addWidget(clear_btn)
        key_gen_layout.addLayout(btn_row, 3, 0, 1, 2)
        
        key_gen_group.setLayout(key_gen_layout)
        left_layout.addWidget(key_gen_group)
        
        params_group = QGroupBox("密钥参数")
        params_layout = QGridLayout()
        params_layout.setSpacing(4)
        
        params_layout.addWidget(QLabel("模数 n:"), 0, 0, Qt.AlignTop)
        self.key_n_edit = QTextEdit()
        self.key_n_edit.setMinimumHeight(40)
        params_layout.addWidget(self.key_n_edit, 0, 1)
        
        params_layout.addWidget(QLabel("公钥 e:"), 1, 0)
        self.key_e_edit = QLineEdit()
        self.key_e_edit.setText("65537")
        params_layout.addWidget(self.key_e_edit, 1, 1)
        
        params_layout.addWidget(QLabel("私钥 d:"), 2, 0, Qt.AlignTop)
        self.key_d_edit = QTextEdit()
        self.key_d_edit.setMinimumHeight(40)
        params_layout.addWidget(self.key_d_edit, 2, 1)
        
        params_layout.addWidget(QLabel("素数:"), 3, 0, Qt.AlignTop)
        self.key_primes_edit = QTextEdit()
        self.key_primes_edit.setMinimumHeight(35)
        params_layout.addWidget(self.key_primes_edit, 3, 1)
        
        gen_params_btn = QPushButton("根据参数生成密钥")
        gen_params_btn.clicked.connect(self._generate_key_from_params)
        params_layout.addWidget(gen_params_btn, 4, 0, 1, 2)
        
        params_group.setLayout(params_layout)
        left_layout.addWidget(params_group)
        
        pem_group = QGroupBox("PEM密钥")
        pem_layout = QVBoxLayout()
        pem_layout.setSpacing(3)
        
        pem_row1 = QHBoxLayout()
        pem_row1.addWidget(QLabel("公钥:"))
        save_pub_btn = QPushButton("保存")
        save_pub_btn.setMaximumWidth(100)
        save_pub_btn.clicked.connect(self._save_public_key)
        pem_row1.addWidget(save_pub_btn)
        load_pub_btn = QPushButton("导入")
        load_pub_btn.setMaximumWidth(100)
        load_pub_btn.clicked.connect(self._load_public_key)
        pem_row1.addWidget(load_pub_btn)
        pem_layout.addLayout(pem_row1)
        
        self.pub_key_edit = QTextEdit()
        self.pub_key_edit.setMaximumHeight(60)
        pem_layout.addWidget(self.pub_key_edit)
        
        pem_row2 = QHBoxLayout()
        pem_row2.addWidget(QLabel("私钥:"))
        save_pri_btn = QPushButton("保存")
        save_pri_btn.setMaximumWidth(100)
        save_pri_btn.clicked.connect(self._save_private_key)
        pem_row2.addWidget(save_pri_btn)
        load_pri_btn = QPushButton("导入")
        load_pri_btn.setMaximumWidth(100)
        load_pri_btn.clicked.connect(self._load_private_key)
        pem_row2.addWidget(load_pri_btn)
        pem_layout.addLayout(pem_row2)
        
        self.pri_key_edit = QTextEdit()
        self.pri_key_edit.setMaximumHeight(60)
        pem_layout.addWidget(self.pri_key_edit)
        
        pem_group.setLayout(pem_layout)
        left_layout.addWidget(pem_group)
        
        left_widget.setLayout(left_layout)
        
        right_widget = QWidget()
        right_layout = QVBoxLayout()
        right_layout.setSpacing(5)
        
        encrypt_group = QGroupBox("加密操作")
        encrypt_layout = QVBoxLayout()
        encrypt_layout.setSpacing(4)
        
        input_row = QHBoxLayout()
        input_row.addWidget(QLabel("明文:"))
        input_row.addStretch()
        import_btn = QPushButton("导入")
        import_btn.setMaximumWidth(100)
        import_btn.clicked.connect(self._import_plaintext)
        input_row.addWidget(import_btn)
        encrypt_layout.addLayout(input_row)
        
        self.plain_edit = QTextEdit()
        encrypt_layout.addWidget(self.plain_edit)
        
        btn_row = QHBoxLayout()
        btn_row.addWidget(QLabel("密文格式:"))
        self.cipher_format_combo = QComboBox()
        self.cipher_format_combo.addItem("Base64", "base64")
        self.cipher_format_combo.addItem("十六进制", "hex")
        self.cipher_format_combo.addItem("十进制", "decimal")
        self.cipher_format_combo.currentIndexChanged.connect(self._on_cipher_format_changed)
        btn_row.addWidget(self.cipher_format_combo)
        btn_row.addStretch()
        enc_btn = QPushButton("加密")
        enc_btn.setMaximumWidth(100)
        enc_btn.clicked.connect(self._encrypt_data)
        btn_row.addWidget(enc_btn)
        encrypt_layout.addLayout(btn_row)
        
        encrypt_layout.addWidget(QLabel("密文:"))
        self.cipher_edit = QTextEdit()
        encrypt_layout.addWidget(self.cipher_edit)
        
        copy_row = QHBoxLayout()
        copy_btn = QPushButton("复制密文")
        copy_btn.clicked.connect(lambda: self._copy_plain_text(self.cipher_edit.toPlainText()))
        copy_row.addWidget(copy_btn)
        copy_row.addStretch()
        encrypt_layout.addLayout(copy_row)
        
        encrypt_group.setLayout(encrypt_layout)
        right_layout.addWidget(encrypt_group)
        
        right_layout.addStretch()
        right_widget.setLayout(right_layout)
        
        splitter.addWidget(self._scroll_area(left_widget, 420))
        splitter.addWidget(right_widget)
        splitter.setSizes([550, 550])
        
        layout.addWidget(splitter)
        widget.setLayout(layout)
        return widget
    
    def _create_decrypt_tab(self):
        """创建解密/攻击标签页 - 左右分栏布局"""
        widget = QWidget()
        layout = QHBoxLayout()
        layout.setSpacing(8)
        
        splitter = QSplitter(Qt.Horizontal)
        
        left_widget = QWidget()
        left_layout = QVBoxLayout()
        left_layout.setSpacing(5)
        
        params_group = QGroupBox("参数输入")
        params_layout = QGridLayout()
        params_layout.setSpacing(4)
        
        param_defs = [
            ("n", "模数 n:", 45),
            ("e", "公钥 e:", 25),
            ("c", "密文 c:", 45),
            ("p", "因子 p:", 35),
            ("d", "私钥 d:", 35)
        ]
        
        self.decrypt_params = {}
        for i, (name, label, height) in enumerate(param_defs):
            params_layout.addWidget(QLabel(label), i, 0, Qt.AlignTop)
            if name == "e":
                edit = QLineEdit()
                edit.setText("65537")
            else:
                edit = QTextEdit()
                edit.setMinimumHeight(height)
            self.decrypt_params[name] = edit
            params_layout.addWidget(edit, i, 1)

        params_btn_row = QHBoxLayout()
        quick_btn = QPushButton("根据已有参数补全")
        quick_btn.setToolTip("支持 p 输入框填入 p,q；或 n+p 推导 q；并自动补全 n/d，存在 c 时计算 m")
        quick_btn.clicked.connect(self._quick_calculate)
        params_btn_row.addWidget(quick_btn)
        import_params_btn = QPushButton("导入参数文件")
        import_params_btn.setToolTip("读取文本文件中的 n/e/c/p/q/d 参数，也可直接拖入文件")
        import_params_btn.clicked.connect(self._import_rsa_params_file)
        params_btn_row.addWidget(import_params_btn)
        clear_params_btn = QPushButton("清空参数")
        clear_params_btn.clicked.connect(self._clear_decrypt_params)
        params_btn_row.addWidget(clear_params_btn)
        params_layout.addLayout(params_btn_row, len(param_defs), 0, 1, 2)
        
        params_group.setLayout(params_layout)
        left_layout.addWidget(params_group)
        
        left_widget.setLayout(left_layout)
        
        right_widget = QWidget()
        right_layout = QVBoxLayout()
        right_layout.setSpacing(5)
        
        attack_group = QGroupBox("攻击方式")
        attack_layout = QVBoxLayout()
        attack_layout.setSpacing(4)
        
        mode_row = QHBoxLayout()
        mode_row.addWidget(QLabel("选择:"))
        self.mode_combo = QComboBox()
        self.mode_combo.setMinimumWidth(260)
        self.mode_combo.addItem("直接解密", "direct")
        
        attack_names = self.attack_loader.get_attack_names()
        for name in attack_names:
            info = self.attack_loader.get_attack_info(name)
            desc = info.get('desc', '') if info else ''
            self.mode_combo.addItem(f"{name}", name)
        
        self.mode_combo.currentIndexChanged.connect(self._on_mode_changed)
        mode_row.addWidget(self.mode_combo)
        
        auto_btn = QPushButton("自动检测")
        auto_btn.setToolTip("根据 n/e 参数自动推荐最佳攻击方法")
        auto_btn.setStyleSheet("""
            QPushButton {
                background-color: #F5F5F5;
                color: #333333;
                border: 1px solid #BDBDBD;
                border-radius: 4px;
                padding: 4px 10px;
            }
            QPushButton:hover {
                background-color: #E3F2FD;
                border-color: #90CAF9;
            }
            QPushButton:pressed {
                background-color: #BBDEFB;
            }
        """)
        auto_btn.clicked.connect(self._on_auto_detect)
        mode_row.addWidget(auto_btn)
        attack_layout.addLayout(mode_row)
        
        self.mode_hint_edit = QTextEdit()
        self.mode_hint_edit.setReadOnly(True)
        self.mode_hint_edit.setAcceptRichText(False)
        self.mode_hint_edit.setMinimumHeight(90)
        self.mode_hint_edit.setMaximumHeight(160)
        self.mode_hint_edit.setStyleSheet("color: #666; background-color: #fafafa;")
        attack_layout.addWidget(self.mode_hint_edit)
        
        self.dynamic_params_widget = QWidget()
        self.dynamic_params_layout = QVBoxLayout()
        self.dynamic_params_layout.setContentsMargins(0, 0, 0, 0)
        self.dynamic_params_layout.setSpacing(4)
        self.dynamic_params_widget.setLayout(self.dynamic_params_layout)
        self.dynamic_params_scroll = self._scroll_area(self.dynamic_params_widget)
        self.dynamic_params_scroll.setMinimumHeight(220)
        attack_layout.addWidget(self.dynamic_params_scroll)
        self.dynamic_param_edits = {}
        
        btn_row = QHBoxLayout()
        decrypt_btn = QPushButton("解密")
        decrypt_btn.clicked.connect(self._execute_decrypt)
        btn_row.addWidget(decrypt_btn)
        self.attack_btn = QPushButton("执行攻击")
        self.attack_btn.clicked.connect(self._execute_attack)
        btn_row.addWidget(self.attack_btn)
        self.pause_attack_btn = QPushButton("暂停攻击")
        self.pause_attack_btn.setEnabled(False)
        self.pause_attack_btn.clicked.connect(self._pause_attack)
        btn_row.addWidget(self.pause_attack_btn)
        clear_btn = QPushButton("清空")
        clear_btn.clicked.connect(self._clear_result)
        btn_row.addWidget(clear_btn)
        attack_layout.addLayout(btn_row)
        
        attack_group.setLayout(attack_layout)
        right_layout.addWidget(attack_group)
        
        result_group = QGroupBox("解密结果")
        result_layout = QVBoxLayout()
        result_layout.setSpacing(4)
        
        format_row = QHBoxLayout()
        format_row.addWidget(QLabel("输出格式:"))
        self.result_format_combo = QComboBox()
        self.result_format_combo.addItem("十进制", "decimal")
        self.result_format_combo.addItem("十六进制", "hex")
        self.result_format_combo.addItem("Base64", "base64")
        self.result_format_combo.currentIndexChanged.connect(self._on_result_format_changed)
        format_row.addWidget(self.result_format_combo)
        format_row.addStretch()
        result_layout.addLayout(format_row)
        
        result_layout.addWidget(QLabel("明文 (整数):"))
        self.result_int_edit = QTextEdit()
        self.result_int_edit.setReadOnly(True)
        self.result_int_edit.setStyleSheet("background-color: #f0f0f0;")
        result_layout.addWidget(self.result_int_edit)
        
        result_layout.addWidget(QLabel("明文 (字符串):"))
        self.result_str_edit = QTextEdit()
        self.result_str_edit.setReadOnly(True)
        self.result_str_edit.setStyleSheet("background-color: #f0f0f0;")
        result_layout.addWidget(self.result_str_edit)
        
        copy_row = QHBoxLayout()
        copy_int_btn = QPushButton("复制整数")
        copy_int_btn.clicked.connect(lambda: self._copy_plain_text(self.result_int_edit.toPlainText()))
        copy_row.addWidget(copy_int_btn)
        copy_str_btn = QPushButton("复制字符串")
        copy_str_btn.clicked.connect(lambda: self._copy_plain_text(self.result_str_edit.toPlainText()))
        copy_row.addWidget(copy_str_btn)
        copy_row.addStretch()
        result_layout.addLayout(copy_row)
        
        result_group.setLayout(result_layout)
        right_layout.addWidget(result_group)
        
        right_layout.addStretch()
        right_widget.setLayout(right_layout)
        
        splitter.addWidget(self._scroll_area(left_widget, 380))
        splitter.addWidget(right_widget)
        splitter.setSizes([400, 600])
        
        layout.addWidget(splitter)
        widget.setLayout(layout)
        return widget
    
    def _on_mode_changed(self, index):
        """解密方式改变"""
        mode = self.mode_combo.currentData()
        info = self.attack_loader.get_attack_info(mode)
        if info and 'hint' in info:
            self.mode_hint_edit.setPlainText(info['hint'])
        else:
            self.mode_hint_edit.setPlainText("需要d或p进行直接解密" if mode == "direct" else "")
        
        self._update_dynamic_params(mode)
    
    def _on_auto_detect(self):
        """自动检测推荐攻击方法"""
        try:
            suggestions = self._auto_detect_attack()
        except Exception as ex:
            QMessageBox.warning(self, "自动检测", f"自动检测失败: {str(ex)}")
            return
        
        if suggestions is None:
            QMessageBox.information(self, "自动检测",
                "请先输入有效的 n（模数）。\n\n提示: n 支持十进制、0x十六进制和Base64格式。")
            return

        if not suggestions:
            QMessageBox.information(self, "自动检测",
                "已读取 n/e，但未检测到明显适用的自动攻击。\n\n可继续补充密文 c、因子 p，或手动选择攻击方式。")
            return
        
        # 构建推荐消息
        msg_lines = ["🔍 自动检测结果:\n"]
        for i, (attack_name, confidence, reason) in enumerate(suggestions[:5], 1):
            stars = "★" * int(confidence * 5) + "☆" * (5 - int(confidence * 5))
            display_name = self._resolve_attack_name(attack_name) or attack_name
            msg_lines.append(f"{i}. [{stars}] {display_name}")
            msg_lines.append(f"   {reason}")
            msg_lines.append("")
        
        msg_lines.append("是否切换到最推荐的方法？")
        msg = "\n".join(msg_lines)
        
        reply = QMessageBox.question(self, "自动检测结果", msg,
                                       QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes and suggestions:
            best = self._resolve_attack_name(suggestions[0][0])
            if best and self._select_attack(best):
                self.status_tip(f"已切换到推荐攻击: {best}")
            else:
                QMessageBox.warning(self, "自动检测", f"未找到推荐攻击: {suggestions[0][0]}")

    def _resolve_attack_name(self, attack_name):
        if self.attack_loader.get_attack_info(attack_name):
            return attack_name
        mapped = ATTACK_ALIASES.get(attack_name)
        if mapped and self.attack_loader.get_attack_info(mapped):
            return mapped
        normalized = str(attack_name).lower().replace('_', '')
        for i in range(self.mode_combo.count()):
            candidate = self.mode_combo.itemData(i)
            if str(candidate).lower().replace('_', '') == normalized:
                return candidate
        return None

    def _select_attack(self, attack_name):
        for i in range(self.mode_combo.count()):
            if self.mode_combo.itemData(i) == attack_name:
                self.mode_combo.setCurrentIndex(i)
                return True
        return False

    def status_tip(self, message):
        parent = self.parent()
        while parent is not None:
            if hasattr(parent, 'statusBar'):
                parent.statusBar().showMessage(message, 3000)
                return
            parent = parent.parent()

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if not urls:
            super().dropEvent(event)
            return
        file_path = urls[0].toLocalFile()
        if file_path:
            self._load_rsa_params_file(file_path)
            event.acceptProposedAction()
        else:
            super().dropEvent(event)

    def eventFilter(self, watched, event):
        if event.type() == QEvent.DragEnter and event.mimeData().hasUrls():
            event.acceptProposedAction()
            return True
        if event.type() == QEvent.Drop and event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            file_path = urls[0].toLocalFile() if urls else ''
            if file_path:
                self._load_rsa_params_file(file_path)
                event.acceptProposedAction()
                return True
        return super().eventFilter(watched, event)

    def _install_file_drop_handlers(self):
        for widget in self.findChildren(QWidget):
            widget.setAcceptDrops(True)
            widget.installEventFilter(self)

    def _copy_plain_text(self, text):
        if not text:
            return
        copy_plain_text(text)
    
    def _update_dynamic_params(self, mode):
        """更新动态参数输入框"""
        self._clear_layout(self.dynamic_params_layout)
        self.dynamic_param_edits = {}
        
        if mode == "direct":
            return
        
        info = self.attack_loader.get_attack_info(mode)
        if not info:
            return
        
        input_fields = info.get('input_fields', [])
        
        basic_fields = ['n', 'e', 'c', 'p', 'd']
        
        for field in input_fields:
            field_name = field.get('name', '')
            if field_name in basic_fields:
                continue
            
            field_label = field.get('label', field_name)
            field_type = field.get('type', 'text')
            placeholder = field.get('placeholder', '')
            default = field.get('default', '')
            
            row_layout = QHBoxLayout()
            row_layout.addWidget(QLabel(f"{field_label}:"), 0, Qt.AlignTop)
            
            if field_type == 'choice':
                combo = QComboBox()
                choices = field.get('choices', [])
                choice_labels = field.get('choice_labels', choices)
                for i, choice in enumerate(choices):
                    label = choice_labels[i] if i < len(choice_labels) else choice
                    combo.addItem(label, choice)
                if default:
                    idx = combo.findData(default)
                    if idx >= 0:
                        combo.setCurrentIndex(idx)
                self.dynamic_param_edits[field_name] = ('combo', combo)
                row_layout.addWidget(combo)
            elif field_type == 'number':
                edit = QLineEdit()
                edit.setPlaceholderText(placeholder)
                if default:
                    edit.setText(str(default))
                self.dynamic_param_edits[field_name] = ('edit', edit)
                row_layout.addWidget(edit)
            else:
                edit = QTextEdit()
                edit.setAcceptRichText(False)
                edit.setPlaceholderText(placeholder)
                edit.setMinimumHeight(56)
                edit.setMaximumHeight(120)
                install_plain_text_copy(edit)
                if default:
                    edit.setPlainText(str(default))
                self.dynamic_param_edits[field_name] = ('text', edit)
                row_layout.addWidget(edit)
            
            self.dynamic_params_layout.addLayout(row_layout)

        self.dynamic_params_layout.addStretch()

    def _clear_layout(self, layout):
        while layout.count():
            item = layout.takeAt(0)
            child_layout = item.layout()
            widget = item.widget()
            if child_layout is not None:
                self._clear_layout(child_layout)
            if widget is not None:
                widget.deleteLater()
    
    def _on_key_format_changed(self):
        """密钥参数格式改变"""
        if self.current_key is None:
            return
        fmt = self.key_format_combo.currentData()
        self.key_n_edit.setPlainText(format_value(self.current_key['n'], fmt))
        self.key_e_edit.setText(format_value(self.current_key['e'], fmt))
        if self.current_key.get('d'):
            self.key_d_edit.setPlainText(format_value(self.current_key['d'], fmt))
        primes = self.current_key.get('primes', [])
        self.key_primes_edit.setPlainText(', '.join(format_value(p, fmt) for p in primes))
    
    def _on_cipher_format_changed(self):
        """密文格式改变"""
        if self.current_cipher is None:
            return
        fmt = self.cipher_format_combo.currentData()
        self.cipher_edit.setPlainText(format_value(self.current_cipher, fmt))
    
    def _on_result_format_changed(self):
        """解密结果格式改变"""
        if self.current_result is None:
            return
        fmt = self.result_format_combo.currentData()
        self.result_int_edit.setPlainText(format_value(self.current_result, fmt))
    
    def _parse_values(self, text):
        """解析逗号分隔的多个值"""
        if not text:
            return []
        values = []
        for v in text.replace('\n', ',').split(','):
            v = v.strip()
            for separator in ('=', '：', ':'):
                if separator in v:
                    v = v.rsplit(separator, 1)[-1].strip()
                    break
            if v:
                val = parse_input_value(v)
                if val is not None:
                    values.append(val)
        return values

    def _dynamic_param_value(self, field_name):
        item = self.dynamic_param_edits.get(field_name)
        if not item:
            return ''
        param_type, widget = item
        if param_type == 'combo':
            return str(widget.currentData())
        if param_type == 'text':
            return widget.toPlainText().strip()
        return widget.text().strip()

    def _basic_param_value(self, field_name):
        widget = self.decrypt_params.get(field_name)
        if widget is None:
            return ''
        if isinstance(widget, QTextEdit):
            return widget.toPlainText().strip()
        return widget.text().strip()

    def _joined_basic_values(self, field_name):
        return ','.join(str(value) for value in self._parse_values(self._basic_param_value(field_name)))

    def _first_param_value(self, field_name):
        values = self._parse_values(self._basic_param_value(field_name))
        return values[0] if values else None

    def _quick_calculate(self):
        """根据常见已知量快速推导RSA参数。"""
        prime_values = self._parse_values(self._basic_param_value('p'))
        p = prime_values[0] if prime_values else None
        q = prime_values[1] if len(prime_values) > 1 else None
        n = self._first_param_value('n')
        e = parse_input_value(self._basic_param_value('e')) if self._basic_param_value('e') else None
        c = self._first_param_value('c')
        d = self._first_param_value('d')

        result = derive_parameters(p=p, q=q, e=e, c=c, n=n, d=d, output_format=self.result_format_combo.currentData())

        if not result.get('success'):
            QMessageBox.warning(self, "参数补全", result.get('text', '参数补全失败'))
            return

        filled = []
        if result.get('n') is not None and not self._basic_param_value('n'):
            self.decrypt_params['n'].setPlainText(str(result['n']))
            filled.append('n')
        if result.get('q') is not None and len(prime_values) < 2:
            self.decrypt_params['p'].setPlainText(f"{result['p']}, {result['q']}" if result.get('p') else str(result['q']))
            filled.append('q')
        if result.get('d') is not None and not self._basic_param_value('d'):
            self.decrypt_params['d'].setPlainText(str(result['d']))
            filled.append('d')
        if result.get('m') is not None:
            self._show_result(result['m'])
            filled.append('m')
        else:
            self._clear_result()

        if filled:
            self.status_tip(f"已补全: {', '.join(filled)}")
        else:
            QMessageBox.information(self, "参数补全", "未发现可补全的空参数框。\n\n提示: 因子 p 输入框可填写 p 或 p, q。")

    def _import_rsa_params_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "导入RSA参数文件", "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            self._load_rsa_params_file(file_path)

    def _load_rsa_params_file(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()
        except Exception as ex:
            QMessageBox.warning(self, "导入失败", f"读取文件失败: {str(ex)}")
            return

        filled = self._fill_rsa_params_from_text(text)
        if filled:
            self.status_tip(f"已导入RSA参数: {', '.join(filled)}")
            self._quick_calculate()
        else:
            QMessageBox.information(self, "导入RSA参数", "未识别到 n/e/c/p/q/d 参数。\n\n支持格式示例: n = 123、p: 123、q = 456、c = 789。")

    def _fill_rsa_params_from_text(self, text):
        if not text:
            return []

        if '-----BEGIN' in text and CRYPTO_AVAILABLE:
            try:
                key = RSA.import_key(text)
                self.decrypt_params['n'].setPlainText(str(key.n))
                self.decrypt_params['e'].setText(str(key.e))
                filled = ['n', 'e']
                if key.has_private():
                    self.decrypt_params['d'].setPlainText(str(key.d))
                    filled.append('d')
                    if getattr(key, 'p', None) and getattr(key, 'q', None):
                        self.decrypt_params['p'].setPlainText(f"{key.p}, {key.q}")
                        filled.append('p,q')
                return filled
            except Exception:
                pass

        labels = {
            'n': ('n', 'modulus', 'module', '模数'),
            'e': ('e', 'public exponent', 'pubexp', '公钥指数', '公钥e'),
            'c': ('c', 'cipher', 'ciphertext', '密文'),
            'd': ('d', 'private exponent', 'privexp', '私钥指数', '私钥d'),
            'p': ('p', 'prime1', 'prime p', '因子p', '素数p'),
            'q': ('q', 'prime2', 'prime q', '因子q', '素数q'),
        }
        found = self._extract_python_rsa_params(text)
        for target, aliases in labels.items():
            if target in found:
                continue
            for alias in aliases:
                pattern = rf'(?im)^\s*["\']?{re.escape(alias)}["\']?\s*[=:：]\s*["\']?([^,;\]\}}\r\n"\']+)'
                match = re.search(pattern, text)
                if match:
                    value = match.group(1).strip()
                    if parse_input_value(value) is not None:
                        found[target] = value
                        break

        filled = []
        for name in ('n', 'e', 'c', 'd'):
            if name in found:
                widget = self.decrypt_params[name]
                if isinstance(widget, QTextEdit):
                    widget.setPlainText(found[name])
                else:
                    widget.setText(found[name])
                filled.append(name)

        primes = []
        if 'p' in found:
            primes.append(found['p'])
        if 'q' in found:
            primes.append(found['q'])
        if primes:
            self.decrypt_params['p'].setPlainText(', '.join(primes))
            filled.append('p,q' if len(primes) > 1 else 'p')

        return filled

    def _extract_python_rsa_params(self, text):
        """安全解析Python脚本中的RSA参数赋值，不执行脚本。"""
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return {}

        found = {}
        wanted = {'n', 'e', 'c', 'd', 'p', 'q'}

        def key_name(node):
            if isinstance(node, ast.Name):
                return node.id.lower()
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return node.value.lower()
            return ''

        def value_text(node):
            if isinstance(node, ast.Constant):
                if isinstance(node.value, int):
                    return str(node.value)
                if isinstance(node.value, str):
                    return node.value.strip()
            if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
                inner = value_text(node.operand)
                return f"-{inner}" if inner else ''
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'int' and node.args:
                raw = value_text(node.args[0])
                base = 10
                if len(node.args) >= 2:
                    base_raw = value_text(node.args[1])
                    if base_raw:
                        base = int(base_raw)
                try:
                    return str(int(raw, base))
                except Exception:
                    return raw
            try:
                segment = ast.get_source_segment(text, node)
            except Exception:
                segment = ''
            return segment.strip() if segment else ''

        def store_param(name, node):
            name = name.lower()
            if name not in wanted or name in found:
                return
            value = value_text(node)
            if value and parse_input_value(value) is not None:
                found[name] = value

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    name = key_name(target)
                    if name in wanted:
                        store_param(name, node.value)
                if isinstance(node.value, ast.Dict):
                    for k, v in zip(node.value.keys, node.value.values):
                        name = key_name(k)
                        if name in wanted:
                            store_param(name, v)
            elif isinstance(node, ast.AnnAssign):
                name = key_name(node.target)
                if name in wanted and node.value is not None:
                    store_param(name, node.value)

        return found
     
    def _generate_key(self):
        """生成RSA密钥 - 后台线程"""
        if self.key_gen_thread is not None and self.key_gen_thread.isRunning():
            QMessageBox.warning(self, "提示", "正在生成密钥，请稍候...")
            return
        
        key_size = self.key_size_spin.value()
        prime_count = self.prime_count_spin.value()
        e = 65537
        
        self.gen_key_btn.setEnabled(False)
        self.gen_key_btn.setText("生成中...")
        
        self.key_gen_worker = RSAKeyGeneratorWorker(key_size, prime_count, e)
        self.key_gen_thread = QThread()
        self.key_gen_worker.moveToThread(self.key_gen_thread)
        
        self.key_gen_thread.started.connect(self.key_gen_worker.run)
        self.key_gen_worker.finished.connect(self._on_key_gen_finished)
        self.key_gen_worker.error.connect(self._on_key_gen_error)
        
        self.key_gen_thread.start()
    
    def _on_key_gen_finished(self, result):
        """密钥生成完成"""
        self.gen_key_btn.setEnabled(True)
        self.gen_key_btn.setText("生成密钥")
        
        if self.key_gen_thread is not None:
            self.key_gen_thread.quit()
            self.key_gen_thread.wait(1000)
            self.key_gen_thread = None
            self.key_gen_worker = None
        
        self.current_key = result
        output_format = self.key_format_combo.currentData()
        
        if result.get('pub_key'):
            self.pub_key_edit.setPlainText(result['pub_key'])
        if result.get('pri_key'):
            self.pri_key_edit.setPlainText(result['pri_key'])
        
        self.key_n_edit.setPlainText(format_value(result['n'], output_format))
        self.key_e_edit.setText(format_value(result['e'], output_format))
        self.key_d_edit.setPlainText(format_value(result['d'], output_format))
        self.key_primes_edit.setPlainText(', '.join(format_value(p, output_format) for p in result['primes']))
        
        QMessageBox.information(self, "成功", f"已生成{self.key_size_spin.value()}位RSA密钥")
    
    def _on_key_gen_error(self, error_msg):
        """密钥生成错误"""
        self.gen_key_btn.setEnabled(True)
        self.gen_key_btn.setText("生成密钥")
        
        if self.key_gen_thread is not None:
            self.key_gen_thread.quit()
            self.key_gen_thread.wait(1000)
            self.key_gen_thread = None
            self.key_gen_worker = None
        
        QMessageBox.warning(self, "错误", f"生成密钥失败: {error_msg}")
    
    def _generate_key_from_params(self):
        """根据输入参数生成RSA密钥 - 支持任意参数组合"""
        output_format = self.key_format_combo.currentData()
        
        n_str = self.key_n_edit.toPlainText().strip()
        e_str = self.key_e_edit.text().strip()
        d_str = self.key_d_edit.toPlainText().strip()
        primes_str = self.key_primes_edit.toPlainText().strip()
        
        n = parse_input_value(n_str) if n_str else None
        e = parse_input_value(e_str) if e_str else None
        d = parse_input_value(d_str) if d_str else None
        primes = self._parse_values(primes_str) if primes_str else []
        
        try:
            if n and e and d and len(primes) >= 2:
                if not self._validate_params(n, e, d, primes):
                    QMessageBox.warning(self, "错误", "输入参数不符合RSA标准")
                    return
                if len(primes) == 2 and CRYPTO_AVAILABLE:
                    key = RSA.construct((n, e, d, primes[0], primes[1]))
                    self.pub_key_edit.setPlainText(key.publickey().export_key().decode())
                    self.pri_key_edit.setPlainText(key.export_key().decode())
                self.current_key = {'n': n, 'e': e, 'd': d, 'primes': primes}
                QMessageBox.information(self, "成功", "已根据完整参数生成密钥")
                
            elif n and e and len(primes) >= 2:
                phi = 1
                for p in primes:
                    phi *= (p - 1)
                d_calc = mod_inverse(e, phi)
                if not d_calc:
                    QMessageBox.warning(self, "错误", "e与φ(n)不互质")
                    return
                if len(primes) == 2 and CRYPTO_AVAILABLE:
                    key = RSA.construct((n, e, d_calc, primes[0], primes[1]))
                    self.pub_key_edit.setPlainText(key.publickey().export_key().decode())
                    self.pri_key_edit.setPlainText(key.export_key().decode())
                self.current_key = {'n': n, 'e': e, 'd': d_calc, 'primes': primes}
                self.key_d_edit.setPlainText(format_value(d_calc, output_format))
                QMessageBox.information(self, "成功", "已根据n、e和素数生成密钥")
                
            elif e and len(primes) >= 2:
                n = 1
                for p in primes:
                    n *= p
                phi = 1
                for p in primes:
                    phi *= (p - 1)
                d_calc = mod_inverse(e, phi)
                if not d_calc:
                    QMessageBox.warning(self, "错误", "e与φ(n)不互质")
                    return
                if len(primes) == 2 and CRYPTO_AVAILABLE:
                    key = RSA.construct((n, e, d_calc, primes[0], primes[1]))
                    self.pub_key_edit.setPlainText(key.publickey().export_key().decode())
                    self.pri_key_edit.setPlainText(key.export_key().decode())
                self.current_key = {'n': n, 'e': e, 'd': d_calc, 'primes': primes}
                self.key_n_edit.setPlainText(format_value(n, output_format))
                self.key_d_edit.setPlainText(format_value(d_calc, output_format))
                QMessageBox.information(self, "成功", f"已根据素数和e生成密钥")
                
            elif n and e and d:
                self.current_key = {'n': n, 'e': e, 'd': d, 'primes': primes}
                if CRYPTO_AVAILABLE:
                    try:
                        key = RSA.construct((n, e, d))
                        self.pub_key_edit.setPlainText(key.publickey().export_key().decode())
                        self.pri_key_edit.setPlainText(key.export_key().decode())
                        if hasattr(key, 'p') and key.p:
                            self.current_key['primes'] = [key.p, key.q]
                            self.key_primes_edit.setPlainText(f"{format_value(key.p, output_format)}, {format_value(key.q, output_format)}")
                    except:
                        pass
                QMessageBox.information(self, "成功", "已根据n、e、d生成密钥")
                
            elif n and e:
                if CRYPTO_AVAILABLE:
                    try:
                        pub_key = RSA.construct((n, e))
                        self.pub_key_edit.setPlainText(pub_key.publickey().export_key().decode())
                    except:
                        pass
                self.pri_key_edit.clear()
                self.current_key = {'n': n, 'e': e, 'd': None, 'primes': primes}
                QMessageBox.information(self, "成功", "已生成公钥（需要素数或私钥才能生成完整密钥）")
                
            elif n and d:
                for test_e in [3, 5, 17, 257, 65537]:
                    if math.gcd(test_e, d) == 1:
                        phi_test = (test_e * d) // math.gcd(test_e, d)
                        if phi_test > 0:
                            e = test_e
                            break
                if e:
                    self.current_key = {'n': n, 'e': e, 'd': d, 'primes': []}
                    self.key_e_edit.setText(str(e))
                    QMessageBox.information(self, "成功", f"已根据n和d生成密钥，推测e={e}")
                else:
                    QMessageBox.warning(self, "提示", "需要e值或素数才能生成完整密钥")
                    
            elif n and len(primes) >= 1:
                p = primes[0]
                if n % p == 0:
                    q = n // p
                    primes = [p, q]
                    phi = (p - 1) * (q - 1)
                    e = 65537
                    if math.gcd(e, phi) != 1:
                        e = 3
                    if math.gcd(e, phi) != 1:
                        e = 17
                    d_calc = mod_inverse(e, phi)
                    if d_calc:
                        self.current_key = {'n': n, 'e': e, 'd': d_calc, 'primes': primes}
                        self.key_e_edit.setText(str(e))
                        self.key_d_edit.setPlainText(format_value(d_calc, output_format))
                        self.key_primes_edit.setPlainText(f"{format_value(p, output_format)}, {format_value(q, output_format)}")
                        if CRYPTO_AVAILABLE:
                            key = RSA.construct((n, e, d_calc, p, q))
                            self.pub_key_edit.setPlainText(key.publickey().export_key().decode())
                            self.pri_key_edit.setPlainText(key.export_key().decode())
                        QMessageBox.information(self, "成功", f"已根据n和因子p生成密钥\nq = {q}")
                    else:
                        QMessageBox.warning(self, "错误", "无法计算私钥d")
                else:
                    QMessageBox.warning(self, "错误", "p不是n的有效因子")
                    
            elif len(primes) >= 2:
                n = 1
                for p in primes:
                    n *= p
                phi = 1
                for p in primes:
                    phi *= (p - 1)
                e = 65537
                if math.gcd(e, phi) != 1:
                    e = 3
                if math.gcd(e, phi) != 1:
                    e = 17
                d_calc = mod_inverse(e, phi)
                if not d_calc:
                    QMessageBox.warning(self, "错误", "无法计算私钥d")
                    return
                if len(primes) == 2 and CRYPTO_AVAILABLE:
                    key = RSA.construct((n, e, d_calc, primes[0], primes[1]))
                    self.pub_key_edit.setPlainText(key.publickey().export_key().decode())
                    self.pri_key_edit.setPlainText(key.export_key().decode())
                self.current_key = {'n': n, 'e': e, 'd': d_calc, 'primes': primes}
                self.key_n_edit.setPlainText(format_value(n, output_format))
                self.key_e_edit.setText(str(e))
                self.key_d_edit.setPlainText(format_value(d_calc, output_format))
                QMessageBox.information(self, "成功", f"已根据素数生成密钥，自动选择e={e}")
                
            elif e:
                key_size = self.key_size_spin.value()
                prime_count = self.prime_count_spin.value()
                
                for _ in range(100):
                    primes = []
                    prime_size = key_size // prime_count
                    for _ in range(prime_count):
                        primes.append(generate_prime(prime_size))
                    
                    n = 1
                    for p in primes:
                        n *= p
                    
                    phi = 1
                    for p in primes:
                        phi *= (p - 1)
                    
                    d = mod_inverse(e, phi)
                    if d is not None:
                        break
                
                if d is None:
                    QMessageBox.warning(self, "错误", "无法生成有效密钥，请尝试不同的e值")
                    return
                
                if len(primes) == 2 and CRYPTO_AVAILABLE:
                    key = RSA.construct((n, e, d, primes[0], primes[1]))
                    self.pub_key_edit.setPlainText(key.publickey().export_key().decode())
                    self.pri_key_edit.setPlainText(key.export_key().decode())
                
                self.current_key = {'n': n, 'e': e, 'd': d, 'primes': primes}
                QMessageBox.information(self, "成功", f"已使用e={e}生成{key_size}位RSA密钥")
                
            elif n:
                QMessageBox.information(self, "提示", "仅有n无法直接生成密钥\n\n请提供以下组合之一：\n- e（自动生成随机密钥）\n- e和素数\n- d和e\n- 因子p")
                
            elif d:
                QMessageBox.information(self, "提示", "仅有d无法生成密钥\n\n请提供以下组合之一：\n- n和d\n- e（自动生成随机密钥）")
                
            else:
                QMessageBox.warning(self, "提示", "请输入任意参数组合：\n- e值（生成随机密钥）\n- n和e（生成公钥）\n- n、e、d（完整密钥）\n- 素数（自动计算n和d）\n- n和因子p（计算q和密钥）")
            
            if self.current_key:
                self.key_n_edit.setPlainText(format_value(self.current_key['n'], output_format))
                self.key_e_edit.setText(str(self.current_key['e']))
                if self.current_key.get('d'):
                    self.key_d_edit.setPlainText(format_value(self.current_key['d'], output_format))
                if self.current_key.get('primes') and len(self.current_key['primes']) >= 2:
                    self.key_primes_edit.setPlainText(', '.join(format_value(p, output_format) for p in self.current_key['primes']))
            
        except Exception as ex:
            QMessageBox.warning(self, "错误", f"生成密钥失败: {str(ex)}")
    
    def _validate_params(self, n, e, d, primes):
        """验证RSA参数"""
        if not n or not e or len(primes) < 2:
            return False
        
        product = 1
        for p in primes:
            if p <= 1:
                return False
            product *= p
        
        if product != n:
            return False
        
        phi = 1
        for p in primes:
            if not is_prime(p):
                return False
            phi *= (p - 1)
        
        if math.gcd(e, phi) != 1:
            return False
        
        if d is not None:
            if (e * d) % phi != 1:
                return False
        
        return True
    
    def _clear_key_fields(self):
        """清空密钥字段"""
        self.current_key = None
        self.pub_key_edit.clear()
        self.pri_key_edit.clear()
        self.key_n_edit.clear()
        self.key_e_edit.setText("65537")
        self.key_d_edit.clear()
        self.key_primes_edit.clear()
    
    def _save_public_key(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "保存公钥", "", "PEM Files (*.pem)")
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(self.pub_key_edit.toPlainText())
                QMessageBox.information(self, "成功", "公钥已保存")
            except Exception as e:
                QMessageBox.warning(self, "错误", f"保存失败: {str(e)}")
    
    def _save_private_key(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "保存私钥", "", "PEM Files (*.pem)")
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(self.pri_key_edit.toPlainText())
                QMessageBox.information(self, "成功", "私钥已保存")
            except Exception as e:
                QMessageBox.warning(self, "错误", f"保存失败: {str(e)}")
    
    def _load_public_key(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "导入公钥", "", "PEM Files (*.pem);;All Files (*)")
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    pem = f.read()
                self.pub_key_edit.setPlainText(pem)
                self._load_key_params_from_pem(pem)
            except Exception as e:
                QMessageBox.warning(self, "错误", f"导入失败: {str(e)}")
    
    def _load_private_key(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "导入私钥", "", "PEM Files (*.pem);;All Files (*)")
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    pem = f.read()
                self.pri_key_edit.setPlainText(pem)
                self._load_key_params_from_pem(pem)
            except Exception as e:
                QMessageBox.warning(self, "错误", f"导入失败: {str(e)}")

    def _load_key_params_from_pem(self, pem):
        """从PEM密钥回填n/e/d，减少导入后手动复制参数。"""
        if not CRYPTO_AVAILABLE:
            return
        key = RSA.import_key(pem)
        output_format = self.key_format_combo.currentData()
        self.key_n_edit.setPlainText(format_value(key.n, output_format))
        self.key_e_edit.setText(format_value(key.e, output_format))
        result = {'n': key.n, 'e': key.e, 'd': None, 'primes': []}
        if key.has_private():
            self.key_d_edit.setPlainText(format_value(key.d, output_format))
            result['d'] = key.d
            if getattr(key, 'p', None) and getattr(key, 'q', None):
                result['primes'] = [key.p, key.q]
                self.key_primes_edit.setPlainText(', '.join(format_value(p, output_format) for p in result['primes']))
            self.pub_key_edit.setPlainText(key.publickey().export_key().decode())
        self.current_key = result
    
    def _import_plaintext(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "选择明文文件", "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    self.plain_edit.setPlainText(f.read())
            except Exception as e:
                QMessageBox.warning(self, "错误", f"读取失败: {str(e)}")
    
    def _encrypt_data(self):
        """加密数据 - 教科书RSA: c = m^e mod n"""
        n_str = self.key_n_edit.toPlainText().strip()
        e_str = self.key_e_edit.text().strip()
        plaintext = self.plain_edit.toPlainText()
        
        if not plaintext:
            QMessageBox.warning(self, "错误", "请输入明文")
            return
        
        n = parse_input_value(n_str) if n_str else None
        e = parse_input_value(e_str) if e_str else 65537
        
        if not n:
            pub_key_pem = self.pub_key_edit.toPlainText()
            if pub_key_pem and CRYPTO_AVAILABLE:
                try:
                    key = RSA.import_key(pub_key_pem)
                    n = key.n
                    e = key.e
                except:
                    pass
        
        if not n:
            QMessageBox.warning(self, "错误", "请先输入模数n或导入公钥")
            return
        
        try:
            m = int.from_bytes(plaintext.encode('utf-8'), 'big')
            
            if m >= n:
                QMessageBox.warning(self, "错误", f"明文太大，需要小于n\n明文位数: {m.bit_length()}\nn位数: {n.bit_length()}")
                return
            
            c = pow(m, e, n)
            self.current_cipher = c
            
            fmt = self.cipher_format_combo.currentData()
            self.cipher_edit.setPlainText(format_value(c, fmt))
            
        except Exception as ex:
            self.cipher_edit.setPlainText(f"加密错误: {str(ex)}")
    
    def _clear_result(self):
        """清空解密结果"""
        self.current_result = None
        self.result_int_edit.clear()
        self.result_str_edit.clear()

    def _clear_decrypt_params(self):
        """清空解密/攻击页参数输入。"""
        for name, widget in self.decrypt_params.items():
            if isinstance(widget, QTextEdit):
                widget.clear()
            else:
                widget.clear()
                if name == 'e':
                    widget.setText("65537")
        self.status_tip("已清空RSA参数")
     
    def _show_result(self, m):
        """显示解密结果"""
        self.current_result = m
        fmt = self.result_format_combo.currentData()
        self.result_int_edit.setPlainText(format_value(m, fmt))
        self.result_str_edit.setPlainText(decode_plaintext(m))
    
    def _execute_decrypt(self):
        """执行直接解密 - 教科书RSA: m = c^d mod n"""
        self._clear_result()
        
        n_text = self.decrypt_params['n'].toPlainText()
        e_text = self.decrypt_params['e'].text()
        c_text = self.decrypt_params['c'].toPlainText()
        d_text = self.decrypt_params['d'].toPlainText()
        p_text = self.decrypt_params['p'].toPlainText()
        
        n_list = self._parse_values(n_text)
        e = parse_input_value(e_text) if e_text else 65537
        c_list = self._parse_values(c_text)
        d_list = self._parse_values(d_text)
        p_list = self._parse_values(p_text)
        
        n = n_list[0] if n_list else None
        c = c_list[0] if c_list else None
        d = d_list[0] if d_list else None
        p = p_list[0] if p_list else None
        
        if not n:
            QMessageBox.warning(self, "错误", "请输入模数n")
            return
        
        if not c:
            QMessageBox.warning(self, "错误", "请输入密文c")
            return
        
        if d:
            try:
                m = pow(c, d, n)
                self._show_result(m)
                return
            except Exception as ex:
                self.result_str_edit.setPlainText(f"解密失败: {str(ex)}")
                return
        
        if p:
            if n % p != 0:
                self.result_str_edit.setPlainText("错误: p不是n的因子")
                return
            
            q = n // p
            phi = (p - 1) * (q - 1)
            
            if math.gcd(e, phi) != 1:
                self.result_str_edit.setPlainText("错误: e与φ(n)不互质")
                return
            
            d_val = mod_inverse(e, phi)
            if d_val:
                m = pow(c, d_val, n)
                self._show_result(m)
                self.result_str_edit.append(f"\n计算过程:\nq = {q}\nφ(n) = {phi}\nd = {d_val}")
                return
        
        self.result_str_edit.setPlainText("直接解密失败: 需要私钥d或因子p\n\n请尝试攻击方式解密")
    
    def _auto_detect_attack(self):
        """根据 n/e 自动推荐最佳攻击方法"""
        n_text = self.decrypt_params['n'].toPlainText().strip()
        e_text = self.decrypt_params['e'].text().strip()
        
        if not n_text:
            return None
        
        n_values = self._parse_values(n_text)
        if not n_values:
            return None

        try:
            n = n_values[0]
            e = parse_input_value(e_text) if e_text else 65537
            if e is None:
                return None
        except Exception:
            return None
        
        n_bits = n.bit_length()
        
        # 按优先级检测
        checks = []
        
        # 1. 已知因子
        p_text = self.decrypt_params['p'].toPlainText().strip()
        if p_text:
            try:
                p = parse_input_value(p_text)
                if p and p > 1 and n % p == 0:
                    checks.append(('known_factor', 1.0, '已知因子 p 可直接分解'))
            except Exception:
                pass
        
        # 2. 广播/共因子类攻击（多组 n,c）
        c_text = self.decrypt_params['c'].toPlainText().strip()
        c_list = [x.strip() for x in c_text.split('\n') if x.strip()]
        n_list = [x.strip() for x in n_text.split('\n') if x.strip()]
        if e in (3, 5, 7) and len(c_list) >= e and len(n_list) >= e:
            checks.append(('broadcast', 0.95, f'e={e} 且至少 {e} 组 n,c → 小指数广播攻击'))
            checks.append(('Hastad广播攻击(sagemath)', 0.7, f'e={e} 且至少 {e} 组 n,c → Hastad 广播攻击'))
        if len(n_list) >= 2:
            checks.append(('Common Prime攻击(sagemath)', 0.65, '多组 n → 可检测是否共享素因子'))
        
        # 3. 小 e（低加密指数攻击模块支持 3、5、7、11...）
        if e in (3, 5, 7, 11, 13, 17):
            confidence = 0.85 if e == 3 else 0.75
            checks.append(('low_exponent', confidence, f'e={e} → 低加密指数攻击'))
        
        # 4. 大 e → Wiener 攻击（d < n^0.25）
        if e * e > n:
            checks.append(('wiener', 0.7, f'e 较大 ({n_bits}bit n) → Wiener 攻击'))
            if n_bits >= 1024:
                checks.append(('extended_wiener', 0.5, '大 n + 大 e → Extended Wiener'))
        
        # 5. Fermat（p,q 接近）
        if n_bits <= 1024:
            checks.append(('fermat', 0.4, f'{n_bits}bit n → 尝试 Fermat 分解'))
        
        # 6. Pollard p-1 / Williams p+1（小因子）
        if n_bits <= 512:
            checks.append(('pollard_p1', 0.35, f'{n_bits}bit n → Pollard p-1'))
            checks.append(('williams_p1', 0.3, f'{n_bits}bit n → Williams p+1'))
        
        # 7. PollardRho（通用）
        if n_bits <= 256:
            checks.append(('pollard_rho', 0.25, f'{n_bits}bit n → PollardRho 分解'))
        
        # 8. 共模攻击（两组相同 n）
        e_values = self._parse_values(e_text)
        if len(n_list) >= 2 and len(set(n_list)) == 1 and len(e_values) >= 2 and len(c_list) >= 2:
            checks.append(('common_modulus', 0.9, '相同 n 不同 e → 共模攻击'))

        # 9. 已知 d 恢复因子
        d_text = self.decrypt_params['d'].toPlainText().strip()
        if d_text:
            checks.append(('已知d恢复因子', 0.9, '已知 n/e/d → 恢复 p,q'))
        
        # 9. CRT 故障攻击（有签名对）
        if 'signature' in n_text.lower() or 'sig' in n_text.lower():
            checks.append(('crt_fault', 0.6, '包含签名信息 → CRT 故障攻击'))
        
        # 10. LSB Oracle（有解密 oracle）
        if 'oracle' in n_text.lower() or 'lsb' in n_text.lower():
            checks.append(('lsb_oracle', 0.6, '包含 oracle 信息 → LSB Oracle 攻击'))
        
        # 按置信度排序
        checks.sort(key=lambda x: -x[1])
        
        return checks
    
    def _execute_attack(self):
        """执行攻击"""
        self._clear_result()
        
        mode = self.mode_combo.currentData()
        
        if mode == "direct":
            self._execute_decrypt()
            return
        
        n_text = self.decrypt_params['n'].toPlainText()
        e_text = self.decrypt_params['e'].text()
        c_text = self.decrypt_params['c'].toPlainText()
        p_text = self.decrypt_params['p'].toPlainText()
        d_text = self.decrypt_params['d'].toPlainText()
        
        n_list = self._parse_values(n_text)
        e_list = self._parse_values(e_text) if e_text else [65537]
        c_list = self._parse_values(c_text)
        p_list = self._parse_values(p_text)
        d_list = self._parse_values(d_text)
        
        n = n_list[0] if n_list else None
        e = e_list[0] if e_list else 65537
        c = c_list[0] if c_list else None
        p = p_list[0] if p_list else None
        d = d_list[0] if d_list else None
        
        info = self.attack_loader.get_attack_info(mode)
        if not info:
            self.result_str_edit.setPlainText(f"未找到攻击模块: {mode}")
            return
        
        input_fields = info.get('input_fields', [])
        params = {}
        
        for field in input_fields:
            field_name = field['name']
            if field_name == 'n':
                params['n'] = str(n) if n else ''
            elif field_name == 'e':
                params['e'] = str(e)
            elif field_name == 'c':
                params['c'] = str(c) if c else ''
            elif field_name == 'p':
                params['p'] = str(p) if p else ''
            elif field_name == 'd':
                params['d'] = str(d) if d else ''
            elif field_name == 'e1':
                params['e1'] = self._dynamic_param_value('e1') or (str(e_list[0]) if e_list else '')
            elif field_name == 'e2':
                params['e2'] = self._dynamic_param_value('e2') or (str(e_list[1]) if len(e_list) > 1 else '')
            elif field_name == 'c1':
                params['c1'] = self._dynamic_param_value('c1') or (str(c_list[0]) if c_list else '')
            elif field_name == 'c2':
                params['c2'] = self._dynamic_param_value('c2') or (str(c_list[1]) if len(c_list) > 1 else '')
            elif field_name == 'data_groups':
                dynamic_groups = self._dynamic_param_value('data_groups')
                if dynamic_groups:
                    params['data_groups'] = dynamic_groups
                else:
                    groups = []
                    for i in range(min(len(n_list), len(c_list))):
                        groups.append(f"{n_list[i]},{e},{c_list[i]}")
                    params['data_groups'] = ';'.join(groups)
            elif field_name == 'n1':
                params['n1'] = self._dynamic_param_value('n1') or (str(n_list[0]) if n_list else '')
            elif field_name == 'n2':
                params['n2'] = self._dynamic_param_value('n2') or (str(n_list[1]) if len(n_list) > 1 else '')
            elif field_name in ('n_list', 'c_list'):
                base_name = field_name.split('_', 1)[0]
                params[field_name] = self._dynamic_param_value(field_name) or self._joined_basic_values(base_name)
            elif field_name in ('m', 'sv', 'sf', 'p_high', 'd_partial', 'lsb_sequence', 'known_part'):
                params[field_name] = self._dynamic_param_value(field_name)
            elif field_name in self.dynamic_param_edits:
                params[field_name] = self._dynamic_param_value(field_name)
        
        self._start_attack(mode, params)
    
    def _start_attack(self, attack_name, params):
        """启动攻击线程"""
        if self.attack_thread is not None and self.attack_thread.isRunning():
            self.attack_thread.quit()
            self.attack_thread.wait(1000)
        
        self.attack_btn.setEnabled(False)
        self.pause_attack_btn.setEnabled(True)
        self.result_str_edit.setPlainText(f"正在执行 {attack_name}...")
        
        self.attack_worker = RSAAttackWorker(self.attack_loader, attack_name, params)
        self.attack_thread = QThread()
        self.attack_worker.moveToThread(self.attack_thread)
        
        self.attack_thread.started.connect(self.attack_worker.run)
        self.attack_worker.finished.connect(self._on_attack_finished)
        self.attack_worker.error.connect(self._on_attack_error)
        
        self.attack_thread.start()

    def _pause_attack(self):
        """停止当前攻击线程。"""
        if self.attack_worker is not None:
            self.attack_worker.cancel()
        if self.attack_thread is not None and self.attack_thread.isRunning():
            self.attack_thread.requestInterruption()
            self.attack_thread.quit()
            if not self.attack_thread.wait(1000):
                self.attack_thread.terminate()
                self.attack_thread.wait(1000)
        self.attack_thread = None
        self.attack_worker = None
        self.attack_btn.setEnabled(True)
        self.pause_attack_btn.setEnabled(False)
        self.result_str_edit.setPlainText("攻击已暂停")
    
    def _on_attack_finished(self, result):
        """攻击完成"""
        self.attack_btn.setEnabled(True)
        self.pause_attack_btn.setEnabled(False)
        
        if self.attack_thread is not None:
            self.attack_thread.quit()
            self.attack_thread.wait(1000)
            self.attack_thread = None
            self.attack_worker = None
        
        parsed = self.attack_loader.parse_attack_result(result)
        text = parsed.get('text', str(result))
        self.result_str_edit.setPlainText(text)
        
        if parsed.get('success'):
            p = parsed.get('p')
            q = parsed.get('q')
            d = parsed.get('d')
            
            if p:
                self.decrypt_params['p'].setPlainText(str(p))
            
            if d:
                self.decrypt_params['d'].setPlainText(str(d))
            
            if p and not d:
                n_text = self.decrypt_params['n'].toPlainText()
                e_text = self.decrypt_params['e'].text()
                c_text = self.decrypt_params['c'].toPlainText()
                
                n_list = self._parse_values(n_text)
                e = parse_input_value(e_text) if e_text else 65537
                c_list = self._parse_values(c_text)
                
                n = n_list[0] if n_list else None
                c = c_list[0] if c_list else None
                
                if n and c:
                    if n % p == 0:
                        q_calc = n // p
                        phi = (p - 1) * (q_calc - 1)
                        
                        if math.gcd(e, phi) == 1:
                            d_calc = mod_inverse(e, phi)
                            if d_calc:
                                self.decrypt_params['d'].setPlainText(str(d_calc))
                                
                                m = pow(c, d_calc, n)
                                self.current_result = m
                                fmt = self.result_format_combo.currentData()
                                self.result_int_edit.setPlainText(format_value(m, fmt))
                                self.result_str_edit.setPlainText(f"{text}\n\n自动解密成功!\n明文(整数): {m}\n明文(字符串): {decode_plaintext(m)}")
                                return
            
            for line in text.split('\n'):
                if "明文(整数):" in line:
                    try:
                        m_str = line.split(":")[1].strip()
                        self.current_result = int(m_str)
                        fmt = self.result_format_combo.currentData()
                        self.result_int_edit.setPlainText(format_value(self.current_result, fmt))
                    except:
                        pass
                    break
    
    def _on_attack_error(self, error_msg):
        """攻击错误"""
        self.attack_btn.setEnabled(True)
        self.pause_attack_btn.setEnabled(False)
        
        if self.attack_thread is not None:
            self.attack_thread.quit()
            self.attack_thread.wait(1000)
            self.attack_thread = None
            self.attack_worker = None
        
        self.result_str_edit.setPlainText(f"攻击出错: {error_msg}")
    
    def closeEvent(self, event):
        """关闭事件"""
        if self.key_gen_thread is not None and self.key_gen_thread.isRunning():
            self.key_gen_thread.quit()
            self.key_gen_thread.wait(2000)
        if self.attack_thread is not None and self.attack_thread.isRunning():
            self._pause_attack()
        event.accept()
