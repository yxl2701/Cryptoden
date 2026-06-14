"""
ECC加解密对话框模块
==================
提供ECC椭圆曲线加密的图形界面，支持加密、解密和攻击功能
"""

from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QTextEdit, QGroupBox, 
                             QFileDialog, QMessageBox, QComboBox, QTabWidget,
                             QWidget, QSplitter, QApplication, QGridLayout)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject
import base64
import hashlib
import secrets

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    ECC_AVAILABLE = True
except ImportError:
    ECC_AVAILABLE = False

from algorithms.asymmetric.ecc.attacks.loader import ECCLoader
from algorithms.asymmetric.ecc import ecc as ecc_module
from .clipboard_utils import copy_plain_text, install_plain_text_copy
from .file_drop_helper import TextFileDropHelper


class ECCAttackWorker(QObject):
    """ECC攻击工作线程"""
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


class ECCDialog(QDialog):
    """ECC加解密对话框"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("ECC工具")
        self.setMinimumSize(1000, 700)
        self.resize(1100, 750)

        self.attack_loader = ECCLoader()
        self.attack_loader.load_all_attacks()
        
        self.private_key = None
        self.public_key = None
        self.attack_thread = None
        self.attack_worker = None
        
        self.setup_ui()
        install_plain_text_copy(self)
        self._install_file_drop_handlers()
        self.check_ecc()
    
    def check_ecc(self):
        if not ECC_AVAILABLE:
            QMessageBox.warning(self, "警告", 
                "未安装cryptography库，ECC加解密功能不可用。\n"
                "请运行: pip install cryptography")
    
    def setup_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setSpacing(5)
        main_layout.setContentsMargins(8, 8, 8, 8)
        
        tabs = QTabWidget()
        tabs.addTab(self._create_encrypt_tab(), "ECC加解密")
        tabs.addTab(self._create_attack_tab(), "ECC攻击")
        
        main_layout.addWidget(tabs)
        self.setLayout(main_layout)
    
    def _create_encrypt_tab(self):
        """创建加解密标签页"""
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(5)
        
        key_group = QGroupBox("密钥管理")
        key_layout = QVBoxLayout()
        key_layout.setSpacing(4)
        
        curve_row = QHBoxLayout()
        curve_row.addWidget(QLabel("椭圆曲线:"))
        self.curve_combo = QComboBox()
        self.curve_combo.addItems([
            "SECP256R1 (P-256)",
            "SECP384R1 (P-384)", 
            "SECP521R1 (P-521)",
            "SECP256K1 (比特币曲线)"
        ])
        curve_row.addWidget(self.curve_combo)
        
        gen_btn = QPushButton("生成密钥对")
        gen_btn.clicked.connect(self.generate_keys)
        curve_row.addWidget(gen_btn)
        
        import_pub_btn = QPushButton("导入公钥")
        import_pub_btn.clicked.connect(self.import_public_key)
        curve_row.addWidget(import_pub_btn)
        
        import_pri_btn = QPushButton("导入私钥")
        import_pri_btn.clicked.connect(self.import_private_key)
        curve_row.addWidget(import_pri_btn)
        
        curve_row.addStretch()
        key_layout.addLayout(curve_row)
        
        key_layout.addWidget(QLabel("公钥:"))
        self.public_key_edit = QTextEdit()
        self.public_key_edit.setMaximumHeight(80)
        self.public_key_edit.setPlaceholderText("点击'生成密钥对'或'导入公钥'")
        key_layout.addWidget(self.public_key_edit)
        
        key_layout.addWidget(QLabel("私钥:"))
        self.private_key_edit = QTextEdit()
        self.private_key_edit.setMaximumHeight(100)
        self.private_key_edit.setPlaceholderText("点击'生成密钥对'或'导入私钥'")
        key_layout.addWidget(self.private_key_edit)
        
        export_row = QHBoxLayout()
        export_pub_btn = QPushButton("导出公钥")
        export_pub_btn.clicked.connect(self.export_public_key)
        export_row.addWidget(export_pub_btn)
        export_pri_btn = QPushButton("导出私钥")
        export_pri_btn.clicked.connect(self.export_private_key)
        export_row.addWidget(export_pri_btn)
        export_row.addStretch()
        key_layout.addLayout(export_row)
        
        key_group.setLayout(key_layout)
        layout.addWidget(key_group)
        
        crypto_group = QGroupBox("加解密操作 (ECIES方案)")
        crypto_layout = QVBoxLayout()
        crypto_layout.setSpacing(4)
        
        op_row = QHBoxLayout()
        op_row.addWidget(QLabel("操作:"))
        self.op_combo = QComboBox()
        self.op_combo.addItems(["加密 (使用公钥)", "解密 (使用私钥)", "签名 (使用私钥)", "验签 (使用公钥)"])
        self.op_combo.currentIndexChanged.connect(self._on_crypto_mode_changed)
        op_row.addWidget(self.op_combo)
        op_row.addStretch()
        crypto_layout.addLayout(op_row)

        verify_row = QHBoxLayout()
        verify_row.addWidget(QLabel("验签原文:"))
        self.verify_message_edit = QLineEdit()
        self.verify_message_edit.setPlaceholderText("验签时填写原始消息；签名/加解密时可留空")
        verify_row.addWidget(self.verify_message_edit)
        crypto_layout.addLayout(verify_row)
        
        crypto_layout.addWidget(QLabel("输入:"))
        self.input_edit = QTextEdit()
        self.input_edit.setPlaceholderText("输入要加密或解密的内容")
        crypto_layout.addWidget(self.input_edit)
        
        exec_row = QHBoxLayout()
        exec_row.addStretch()
        exec_btn = QPushButton("执行")
        exec_btn.clicked.connect(self.execute)
        exec_row.addWidget(exec_btn)
        crypto_layout.addLayout(exec_row)
        
        crypto_layout.addWidget(QLabel("输出:"))
        self.output_edit = QTextEdit()
        self.output_edit.setReadOnly(True)
        self.output_edit.setStyleSheet("background-color: #f0f0f0;")
        crypto_layout.addWidget(self.output_edit)
        
        copy_row = QHBoxLayout()
        copy_btn = QPushButton("复制结果")
        copy_btn.clicked.connect(lambda: copy_plain_text(self.output_edit.toPlainText()))
        copy_row.addWidget(copy_btn)
        copy_row.addStretch()
        crypto_layout.addLayout(copy_row)
        
        crypto_group.setLayout(crypto_layout)
        layout.addWidget(crypto_group)
        
        widget.setLayout(layout)
        self._on_crypto_mode_changed(0)
        return widget

    def _on_crypto_mode_changed(self, index):
        if hasattr(self, 'verify_message_edit'):
            self.verify_message_edit.setVisible(index == 3)
    
    def _create_attack_tab(self):
        """创建攻击标签页"""
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
        self.attack_params_layout = params_layout
        self.attack_param_widgets = {}
        
        params_group.setLayout(params_layout)
        left_layout.addWidget(params_group)
        
        attack_group = QGroupBox("攻击方式")
        attack_layout = QVBoxLayout()
        attack_layout.setSpacing(4)
        
        mode_row = QHBoxLayout()
        mode_row.addWidget(QLabel("选择:"))
        self.attack_mode_combo = QComboBox()
        
        attack_names = self.attack_loader.get_attack_names()
        for name in attack_names:
            info = self.attack_loader.get_attack_info(name)
            desc = info.get('desc', '') if info else ''
            self.attack_mode_combo.addItem(f"{name}", name)
        
        self.attack_mode_combo.currentIndexChanged.connect(self._on_attack_mode_changed)
        mode_row.addWidget(self.attack_mode_combo)
        attack_layout.addLayout(mode_row)
        
        self.attack_hint_label = QLabel()
        self.attack_hint_label.setStyleSheet("color: #666;")
        self.attack_hint_label.setWordWrap(True)
        attack_layout.addWidget(self.attack_hint_label)
        
        btn_row = QHBoxLayout()
        self.execute_attack_btn = QPushButton("执行攻击")
        self.execute_attack_btn.clicked.connect(self._execute_attack)
        btn_row.addWidget(self.execute_attack_btn)
        clear_btn = QPushButton("清空")
        clear_btn.clicked.connect(self._clear_attack_result)
        btn_row.addWidget(clear_btn)
        attack_layout.addLayout(btn_row)
        
        attack_group.setLayout(attack_layout)
        left_layout.addWidget(attack_group)
        
        left_layout.addStretch()
        left_widget.setLayout(left_layout)
        
        right_widget = QWidget()
        right_layout = QVBoxLayout()
        right_layout.setSpacing(5)
        
        result_group = QGroupBox("攻击结果")
        result_layout = QVBoxLayout()
        result_layout.setSpacing(4)
        
        result_layout.addWidget(QLabel("输出:"))
        self.attack_result_edit = QTextEdit()
        self.attack_result_edit.setReadOnly(True)
        self.attack_result_edit.setStyleSheet("background-color: #f0f0f0;")
        result_layout.addWidget(self.attack_result_edit)
        
        copy_row = QHBoxLayout()
        copy_btn = QPushButton("复制结果")
        copy_btn.clicked.connect(lambda: copy_plain_text(self.attack_result_edit.toPlainText()))
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
        
        layout.addWidget(splitter)
        widget.setLayout(layout)
        
        if attack_names:
            self._on_attack_mode_changed(0)
        
        return widget
    
    def _on_attack_mode_changed(self, index):
        """攻击方式改变"""
        mode = self.attack_mode_combo.currentData()
        info = self.attack_loader.get_attack_info(mode)
        if info and 'hint' in info:
            self.attack_hint_label.setText(info['hint'][:200])
        else:
            self.attack_hint_label.setText("")
        self._update_attack_params(mode)

    def _update_attack_params(self, mode):
        while self.attack_params_layout.count():
            item = self.attack_params_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

        self.attack_param_widgets = {}
        info = self.attack_loader.get_attack_info(mode)
        if not info:
            return

        fields = info.get('input_fields', [])
        for row, field in enumerate(fields):
            name = field.get('name', '')
            label = field.get('label', name)
            field_type = field.get('type', 'text')
            placeholder = field.get('placeholder', '')
            default = field.get('default', '')

            self.attack_params_layout.addWidget(QLabel(label), row, 0)
            if field_type == 'choice':
                widget = QComboBox()
                choices = field.get('choices', [])
                labels = field.get('choice_labels', choices)
                for i, choice in enumerate(choices):
                    widget.addItem(labels[i] if i < len(labels) else choice, choice)
                if default:
                    idx = widget.findData(default)
                    if idx >= 0:
                        widget.setCurrentIndex(idx)
                self.attack_param_widgets[name] = ('combo', widget)
            elif field_type == 'textarea':
                widget = QTextEdit()
                widget.setMaximumHeight(90)
                widget.setPlaceholderText(placeholder)
                if default:
                    widget.setPlainText(str(default))
                self.attack_param_widgets[name] = ('text', widget)
            else:
                widget = QLineEdit()
                widget.setPlaceholderText(placeholder)
                if default:
                    widget.setText(str(default))
                self.attack_param_widgets[name] = ('edit', widget)
            self.attack_params_layout.addWidget(widget, row, 1)
    
    def _clear_attack_result(self):
        """清空攻击结果"""
        self.attack_result_edit.clear()

    def _install_file_drop_handlers(self):
        self.input_drop_helper = TextFileDropHelper(self, self.input_edit)
        self.public_key_drop_helper = TextFileDropHelper(self, self.public_key_edit)
        self.private_key_drop_helper = TextFileDropHelper(self, self.private_key_edit)
    
    def _execute_attack(self):
        """执行攻击"""
        self._clear_attack_result()
        
        mode = self.attack_mode_combo.currentData()
        if not mode:
            self.attack_result_edit.setPlainText("请选择攻击方式")
            return
        
        info = self.attack_loader.get_attack_info(mode)
        if not info:
            self.attack_result_edit.setPlainText(f"未找到攻击模块: {mode}")
            return
        
        params = {}
        for name, (kind, widget) in self.attack_param_widgets.items():
            if kind == 'combo':
                text = str(widget.currentData()).strip()
            elif kind == 'text':
                text = widget.toPlainText().strip()
            else:
                text = widget.text().strip()
            if text:
                params[name] = text
        
        self._start_attack(mode, params)
    
    def _start_attack(self, attack_name, params):
        """启动攻击线程"""
        if self.attack_thread is not None and self.attack_thread.isRunning():
            self.attack_thread.quit()
            self.attack_thread.wait(1000)
        
        self.execute_attack_btn.setEnabled(False)
        self.attack_result_edit.setPlainText(f"正在执行 {attack_name}...")
        
        self.attack_worker = ECCAttackWorker(self.attack_loader, attack_name, params)
        self.attack_thread = QThread()
        self.attack_worker.moveToThread(self.attack_thread)
        
        self.attack_thread.started.connect(self.attack_worker.run)
        self.attack_worker.finished.connect(self._on_attack_finished)
        self.attack_worker.error.connect(self._on_attack_error)
        
        self.attack_thread.start()
    
    def _on_attack_finished(self, result):
        """攻击完成"""
        self.execute_attack_btn.setEnabled(True)
        
        if self.attack_thread is not None:
            self.attack_thread.quit()
            self.attack_thread.wait(1000)
            self.attack_thread = None
            self.attack_worker = None
        
        parsed = self.attack_loader.parse_attack_result(result)
        text = parsed.get('text', str(result))
        self.attack_result_edit.setPlainText(text)
    
    def _on_attack_error(self, error_msg):
        """攻击错误"""
        self.execute_attack_btn.setEnabled(True)
        
        if self.attack_thread is not None:
            self.attack_thread.quit()
            self.attack_thread.wait(1000)
            self.attack_thread = None
            self.attack_worker = None
        
        self.attack_result_edit.setPlainText(f"攻击出错: {error_msg}")
    
    def get_curve(self):
        curves = {
            0: ec.SECP256R1(),
            1: ec.SECP384R1(),
            2: ec.SECP521R1(),
            3: ec.SECP256K1()
        }
        return curves.get(self.curve_combo.currentIndex(), ec.SECP256R1())
    
    def generate_keys(self):
        if not ECC_AVAILABLE:
            return
        
        try:
            curve = self.get_curve()
            self.private_key = ec.generate_private_key(curve, default_backend())
            self.public_key = self.private_key.public_key()
            
            private_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            self.private_key_edit.setPlainText(private_pem.decode())
            self.public_key_edit.setPlainText(public_pem.decode())
            
            curve_name = self.curve_combo.currentText()
            QMessageBox.information(self, "成功", f"已生成{curve_name}密钥对")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"生成密钥失败: {str(e)}")
    
    def import_public_key(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "选择公钥文件", "", "PEM Files (*.pem);;All Files (*)")
        if file_path:
            try:
                with open(file_path, 'rb') as f:
                    key_data = f.read()
                self.public_key = serialization.load_pem_public_key(key_data, backend=default_backend())
                self.public_key_edit.setPlainText(key_data.decode())
                QMessageBox.information(self, "成功", "公钥导入成功")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"导入公钥失败: {str(e)}")
    
    def import_private_key(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "选择私钥文件", "", "PEM Files (*.pem);;All Files (*)")
        if file_path:
            try:
                with open(file_path, 'rb') as f:
                    key_data = f.read()
                self.private_key = serialization.load_pem_private_key(key_data, password=None, backend=default_backend())
                self.public_key = self.private_key.public_key()
                self.private_key_edit.setPlainText(key_data.decode())
                
                public_pem = self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                self.public_key_edit.setPlainText(public_pem.decode())
                
                QMessageBox.information(self, "成功", "私钥导入成功")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"导入私钥失败: {str(e)}")
    
    def export_public_key(self):
        if not self.public_key_edit.toPlainText():
            QMessageBox.warning(self, "警告", "没有公钥可导出")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(self, "保存公钥", "ecc_public_key.pem", "PEM Files (*.pem)")
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(self.public_key_edit.toPlainText())
                QMessageBox.information(self, "成功", f"公钥已保存到: {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"导出失败: {str(e)}")
    
    def export_private_key(self):
        if not self.private_key_edit.toPlainText():
            QMessageBox.warning(self, "警告", "没有私钥可导出")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(self, "保存私钥", "ecc_private_key.pem", "PEM Files (*.pem)")
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(self.private_key_edit.toPlainText())
                QMessageBox.information(self, "成功", f"私钥已保存到: {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"导出失败: {str(e)}")
    
    def execute(self):
        if not ECC_AVAILABLE:
            self.output_edit.setPlainText("错误: 未安装cryptography库")
            return
        
        input_text = self.input_edit.toPlainText()
        if not input_text:
            self.output_edit.setPlainText("请输入内容")
            return
        
        try:
            if self.op_combo.currentIndex() == 0:
                self.encrypt_data(input_text)
            elif self.op_combo.currentIndex() == 1:
                self.decrypt_data(input_text)
            elif self.op_combo.currentIndex() == 2:
                self.sign_data(input_text)
            else:
                self.verify_signature(input_text)
        except Exception as e:
            self.output_edit.setPlainText(f"错误: {str(e)}")
    
    def encrypt_data(self, plaintext):
        if not self.public_key:
            key_text = self.public_key_edit.toPlainText()
            if key_text:
                self.public_key = serialization.load_pem_public_key(
                    key_text.encode(), backend=default_backend())
            else:
                self.output_edit.setPlainText("请先导入或生成公钥")
                return
        
        ephemeral_key = ec.generate_private_key(self.public_key.curve, default_backend())
        shared_key = ephemeral_key.exchange(ec.ECDH(), self.public_key)
        
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ecies',
            backend=default_backend()
        ).derive(shared_key)
        
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(derived_key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        
        ephemeral_public = ephemeral_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        
        result = base64.b64encode(ephemeral_public + iv + ciphertext).decode()
        self.output_edit.setPlainText(result)
    
    def decrypt_data(self, ciphertext):
        if not self.private_key:
            key_text = self.private_key_edit.toPlainText()
            if key_text:
                self.private_key = serialization.load_pem_private_key(
                    key_text.encode(), password=None, backend=default_backend())
            else:
                self.output_edit.setPlainText("请先导入或生成私钥")
                return
        
        data = base64.b64decode(ciphertext)
        
        key_size = self.private_key.curve.key_size
        public_key_size = (key_size + 7) // 8 * 2 + 1
        
        ephemeral_public_bytes = data[:public_key_size]
        iv = data[public_key_size:public_key_size + 16]
        actual_ciphertext = data[public_key_size + 16:]
        
        ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_bytes(
            self.private_key.curve, ephemeral_public_bytes)
        
        shared_key = self.private_key.exchange(ec.ECDH(), ephemeral_public)
        
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ecies',
            backend=default_backend()
        ).derive(shared_key)
        
        cipher = Cipher(algorithms.AES(derived_key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        
        self.output_edit.setPlainText(plaintext.decode())

    def sign_data(self, message):
        private_key_text = self.private_key_edit.toPlainText().strip()
        if not private_key_text:
            self.output_edit.setPlainText("请先导入或生成私钥")
            return
        self.output_edit.setPlainText(ecc_module.sign(message, private_key=private_key_text))

    def verify_signature(self, signature):
        public_key_text = self.public_key_edit.toPlainText().strip()
        message = self.verify_message_edit.text()
        if not public_key_text:
            self.output_edit.setPlainText("请先导入或生成公钥")
            return
        if not message:
            self.output_edit.setPlainText("请填写验签原文")
            return
        self.output_edit.setPlainText(ecc_module.verify(message, signature, public_key=public_key_text))
    
    def closeEvent(self, event):
        """关闭事件"""
        if self.attack_thread is not None and self.attack_thread.isRunning():
            self.attack_thread.quit()
            self.attack_thread.wait(2000)
        event.accept()
