"""
对称密码加解密对话框模块
======================
提供AES、DES等对称加密的图形界面
"""

from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QPushButton, QTextEdit, QGroupBox,
                             QComboBox, QMessageBox)
from PyQt5.QtCore import Qt
import base64
from .clipboard_utils import copy_plain_text, install_plain_text_copy
from .file_drop_helper import TextFileDropHelper

try:
    from Crypto.Cipher import AES, DES, DES3
    from Crypto.Util.Padding import pad, unpad
    from Crypto import Random
    SYMMETRIC_AVAILABLE = True
except ImportError:
    SYMMETRIC_AVAILABLE = False


class SymmetricDialog(QDialog):
    """
    对称密码加解密对话框类
    
    支持的算法:
    - AES (128/192/256位)
    - DES
    - 3DES
    
    支持的模式:
    - ECB (电子密码本模式)
    - CBC (密码分组链接模式)
    - CTR (计数器模式)
    """
    
    def __init__(self, parent=None, initial_algorithm=None):
        super().__init__(parent)
        self.setWindowTitle("对称密码加解密")
        self.setMinimumSize(700, 550)
        self.setup_ui()
        install_plain_text_copy(self)
        self.input_drop_helper = TextFileDropHelper(self, self.input_edit)
        if initial_algorithm:
            idx = self.algo_combo.findText(initial_algorithm)
            if idx >= 0:
                self.algo_combo.setCurrentIndex(idx)
        self.check_crypto()
    
    def check_crypto(self):
        if not SYMMETRIC_AVAILABLE:
            QMessageBox.warning(self, "警告", 
                "未安装pycryptodome库，对称密码功能不可用。\n"
                "请运行: pip install pycryptodome")
    
    def setup_ui(self):
        layout = QVBoxLayout()

        self.byte_formats = ["UTF-8文本", "Hex", "Base64", "字节流(\\xNN)"]
        
        # 算法设置区域
        algo_group = QGroupBox("算法设置")
        algo_layout = QVBoxLayout()
        
        # 算法选择
        algo_row = QHBoxLayout()
        algo_row.addWidget(QLabel("算法:"))
        self.algo_combo = QComboBox()
        self.algo_combo.addItems([
            "AES-128", "AES-192", "AES-256", 
            "DES", "3DES", 
            "Blowfish", "RC4", "ChaCha20", "Fernet", "XOR"
        ])
        self.algo_combo.currentIndexChanged.connect(self.on_algo_changed)
        algo_row.addWidget(self.algo_combo)
        
        algo_row.addWidget(QLabel("模式:"))
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["ECB", "CBC", "CTR"])
        algo_row.addWidget(self.mode_combo)
        
        algo_row.addStretch()
        algo_layout.addLayout(algo_row)
        
        # 密钥输入
        key_row = QHBoxLayout()
        key_row.addWidget(QLabel("密钥:"))
        self.key_edit = QLineEdit()
        self.key_edit.setPlaceholderText("输入密钥（将自动处理为合适长度）")
        key_row.addWidget(self.key_edit)

        key_row.addWidget(QLabel("编码:"))
        self.key_format_combo = QComboBox()
        self.key_format_combo.addItems(self.byte_formats)
        self.key_format_combo.setCurrentText("Hex")
        key_row.addWidget(self.key_format_combo)

        gen_key_btn = QPushButton("生成随机密钥")
        gen_key_btn.clicked.connect(self.generate_key)
        key_row.addWidget(gen_key_btn)
        algo_layout.addLayout(key_row)
        
        # IV输入（CBC模式需要）
        iv_row = QHBoxLayout()
        iv_row.addWidget(QLabel("IV:"))
        self.iv_edit = QLineEdit()
        self.iv_edit.setPlaceholderText("CBC模式需要IV（留空自动生成）")
        iv_row.addWidget(self.iv_edit)

        iv_row.addWidget(QLabel("编码:"))
        self.iv_format_combo = QComboBox()
        self.iv_format_combo.addItems(self.byte_formats)
        self.iv_format_combo.setCurrentText("Hex")
        iv_row.addWidget(self.iv_format_combo)

        gen_iv_btn = QPushButton("生成IV")
        gen_iv_btn.clicked.connect(self.generate_iv)
        iv_row.addWidget(gen_iv_btn)
        algo_layout.addLayout(iv_row)

        format_hint = QLabel("密钥/IV 支持 UTF-8、Hex、Base64、\\xNN 字节流；密文输入输出可按下方格式切换")
        format_hint.setWordWrap(True)
        algo_layout.addWidget(format_hint)
        
        algo_group.setLayout(algo_layout)
        layout.addWidget(algo_group)
        
        # 加解密操作区域
        op_group = QGroupBox("加解密操作")
        op_layout = QVBoxLayout()
        
        # 操作选择
        op_row = QHBoxLayout()
        op_row.addWidget(QLabel("操作:"))
        self.op_combo = QComboBox()
        self.op_combo.addItems(["加密", "解密"])
        op_row.addWidget(self.op_combo)
        op_row.addWidget(QLabel("输入格式:"))
        self.input_format_combo = QComboBox()
        self.input_format_combo.addItems(self.byte_formats)
        self.input_format_combo.setCurrentText("UTF-8文本")
        op_row.addWidget(self.input_format_combo)

        op_row.addWidget(QLabel("输出格式:"))
        self.output_format_combo = QComboBox()
        self.output_format_combo.addItems(self.byte_formats)
        self.output_format_combo.setCurrentText("Base64")
        op_row.addWidget(self.output_format_combo)
        op_row.addStretch()
        op_layout.addLayout(op_row)
        
        # 输入
        op_layout.addWidget(QLabel("输入:"))
        self.input_edit = QTextEdit()
        self.input_edit.setPlaceholderText("输入要加密或解密的内容")
        op_layout.addWidget(self.input_edit)
        
        # 执行按钮
        exec_row = QHBoxLayout()
        exec_row.addStretch()
        exec_btn = QPushButton("执行")
        exec_btn.clicked.connect(self.execute)
        exec_row.addWidget(exec_btn)
        op_layout.addLayout(exec_row)
        
        # 输出
        op_layout.addWidget(QLabel("输出:"))
        self.output_edit = QTextEdit()
        self.output_edit.setReadOnly(True)
        op_layout.addWidget(self.output_edit)
        
        op_group.setLayout(op_layout)
        layout.addWidget(op_group)
        
        # 底部按钮
        bottom_layout = QHBoxLayout()
        bottom_layout.addStretch()
        
        copy_btn = QPushButton("复制结果")
        copy_btn.clicked.connect(self.copy_result)
        bottom_layout.addWidget(copy_btn)
        
        close_btn = QPushButton("关闭")
        close_btn.clicked.connect(self.close)
        bottom_layout.addWidget(close_btn)
        
        layout.addLayout(bottom_layout)
        
        self.setLayout(layout)
    
    def on_algo_changed(self):
        algo = self.algo_combo.currentText()
        if algo.startswith("AES"):
            self.iv_edit.setPlaceholderText("CBC模式需要16字节IV（留空自动生成）")
        elif algo == "DES":
            self.iv_edit.setPlaceholderText("CBC模式需要8字节IV（留空自动生成）")
        elif algo == "3DES":
            self.iv_edit.setPlaceholderText("CBC模式需要8字节IV（留空自动生成）")

        if algo == "Fernet":
            self.key_format_combo.setCurrentText("Base64")
            self.input_format_combo.setCurrentText("UTF-8文本")
            self.output_format_combo.setCurrentText("Base64")
    
    def get_key_size(self):
        algo = self.algo_combo.currentText()
        sizes = {
            "AES-128": 16,
            "AES-192": 24,
            "AES-256": 32,
            "DES": 8,
            "3DES": 24,
            "Blowfish": 16,
            "RC4": 16,
            "ChaCha20": 32,
            "Fernet": 32,
            "XOR": 16
        }
        return sizes.get(algo, 16)
    
    def get_block_size(self):
        algo = self.algo_combo.currentText()
        if algo.startswith("AES"):
            return 16
        else:
            return 8
    
    def generate_key(self):
        if self.algo_combo.currentText() == "Fernet":
            try:
                from cryptography.fernet import Fernet
                key = Fernet.generate_key()
                self.key_edit.setText(self.format_bytes(key, self.key_format_combo.currentText()))
                return
            except ImportError:
                pass
        key_size = self.get_key_size()
        key = Random.get_random_bytes(key_size)
        self.key_edit.setText(self.format_bytes(key, self.key_format_combo.currentText()))
    
    def generate_iv(self):
        block_size = self.get_block_size()
        iv = Random.get_random_bytes(block_size)
        self.iv_edit.setText(self.format_bytes(iv, self.iv_format_combo.currentText()))

    def clean_hex_text(self, text):
        cleaned = "".join(ch for ch in text.strip() if not ch.isspace())
        if cleaned.startswith("0x") or cleaned.startswith("0X"):
            cleaned = cleaned[2:]
        return cleaned

    def parse_byte_stream(self, text):
        cleaned = text.strip()
        if not cleaned:
            return b""

        if "\\x" in cleaned:
            hex_text = cleaned.replace("\\x", "")
            hex_text = self.clean_hex_text(hex_text)
            return bytes.fromhex(hex_text)

        parts = [part for part in cleaned.replace(",", " ").split() if part]
        if parts:
            values = []
            for part in parts:
                token = part[2:] if part.lower().startswith("0x") else part
                base = 16 if any(c in 'abcdefABCDEF' for c in token) else 10
                values.append(int(token, base))
            return bytes(values)

        return bytes.fromhex(self.clean_hex_text(cleaned))

    def parse_bytes(self, text, fmt):
        if fmt == "UTF-8文本":
            return text.encode('utf-8')
        if fmt == "Hex":
            return bytes.fromhex(self.clean_hex_text(text))
        if fmt == "Base64":
            return base64.b64decode(text.strip())
        if fmt == "字节流(\\xNN)":
            return self.parse_byte_stream(text)
        raise ValueError(f"不支持的格式: {fmt}")

    def format_bytes(self, data, fmt):
        if fmt == "UTF-8文本":
            return data.decode('utf-8', errors='replace')
        if fmt == "Hex":
            return data.hex()
        if fmt == "Base64":
            return base64.b64encode(data).decode('ascii')
        if fmt == "字节流(\\xNN)":
            return "".join(f"\\x{byte:02x}" for byte in data)
        raise ValueError(f"不支持的格式: {fmt}")
    
    def prepare_key(self):
        key_text = self.key_edit.text()
        key_size = self.get_key_size()
        
        if not key_text:
            return None
        
        try:
            key_bytes = self.parse_bytes(key_text, self.key_format_combo.currentText())
            if len(key_bytes) < key_size:
                key_bytes = key_bytes.ljust(key_size, b'\0')
            elif len(key_bytes) > key_size:
                key_bytes = key_bytes[:key_size]
            return key_bytes
        except:
            return None
    
    def prepare_iv(self):
        iv_text = self.iv_edit.text()
        block_size = self.get_block_size()
        
        if not iv_text:
            iv = Random.get_random_bytes(block_size)
            self.iv_edit.setText(self.format_bytes(iv, self.iv_format_combo.currentText()))
            return iv
        
        try:
            iv_bytes = self.parse_bytes(iv_text, self.iv_format_combo.currentText())
            if len(iv_bytes) < block_size:
                iv_bytes = iv_bytes.ljust(block_size, b'\0')
            elif len(iv_bytes) > block_size:
                iv_bytes = iv_bytes[:block_size]
            return iv_bytes
        except:
            return Random.get_random_bytes(block_size)

    def parse_cipher_input(self, input_text, mode):
        input_format = self.input_format_combo.currentText()
        if mode == "CBC" and ":" in input_text:
            iv_text, ciphertext_text = input_text.split(":", 1)
            iv = self.parse_bytes(iv_text, input_format)
            self.iv_edit.setText(self.format_bytes(iv, self.iv_format_combo.currentText()))
            return iv, self.parse_bytes(ciphertext_text, input_format)
        return None, self.parse_bytes(input_text, input_format)

    def format_cipher_output(self, result, mode, iv=None):
        output_format = self.output_format_combo.currentText()
        ciphertext = self.format_bytes(result, output_format)
        if mode == "CBC" and iv is not None:
            return f"{self.format_bytes(iv, output_format)}:{ciphertext}"
        return ciphertext
    
    def get_cipher(self, key, iv=None):
        algo = self.algo_combo.currentText()
        mode = self.mode_combo.currentText()
        
        if algo.startswith("AES"):
            if mode == "ECB":
                return AES.new(key, AES.MODE_ECB)
            elif mode == "CBC":
                return AES.new(key, AES.MODE_CBC, iv)
            elif mode == "CTR":
                return AES.new(key, AES.MODE_CTR, nonce=iv[:8] if iv else None)
        elif algo == "DES":
            if mode == "ECB":
                return DES.new(key, DES.MODE_ECB)
            elif mode == "CBC":
                return DES.new(key, DES.MODE_CBC, iv)
            elif mode == "CTR":
                return DES.new(key, DES.MODE_CTR, nonce=iv[:4] if iv else None)
        elif algo == "3DES":
            if mode == "ECB":
                return DES3.new(key, DES3.MODE_ECB)
            elif mode == "CBC":
                return DES3.new(key, DES3.MODE_CBC, iv)
            elif mode == "CTR":
                return DES3.new(key, DES3.MODE_CTR, nonce=iv[:4] if iv else None)
        elif algo == "Blowfish":
            from Crypto.Cipher import Blowfish
            if mode == "ECB":
                return Blowfish.new(key, Blowfish.MODE_ECB)
            elif mode == "CBC":
                return Blowfish.new(key, Blowfish.MODE_CBC, iv)
        elif algo == "ChaCha20":
            from Crypto.Cipher import ChaCha20
            return ChaCha20.new(key=key, nonce=iv[:12] if iv else None)
        
        return None
    
    def execute(self):
        if not SYMMETRIC_AVAILABLE:
            self.output_edit.setPlainText("错误: 未安装pycryptodome库")
            return
        
        algo = self.algo_combo.currentText()
        
        # 特殊处理XOR密码
        if algo == "XOR":
            self.execute_xor()
            return
        
        # 特殊处理Fernet
        if algo == "Fernet":
            self.execute_fernet()
            return
        
        # 特殊处理RC4
        if algo == "RC4":
            self.execute_rc4()
            return
        
        key = self.prepare_key()
        if not key:
            self.output_edit.setPlainText("错误: 请输入有效的密钥")
            return
        
        input_text = self.input_edit.toPlainText()
        if not input_text:
            self.output_edit.setPlainText("请输入内容")
            return
        
        mode = self.mode_combo.currentText()
        is_encrypt = self.op_combo.currentIndex() == 0
        
        try:
            iv = None
            if mode in ["CBC", "CTR"]:
                iv = self.prepare_iv()
            
            cipher = self.get_cipher(key, iv)
            
            if is_encrypt:
                data = self.parse_bytes(input_text, self.input_format_combo.currentText())
                if mode != "CTR":
                    data = pad(data, self.get_block_size())
                result = cipher.encrypt(data)
                output = self.format_cipher_output(result, mode, iv)
            else:
                parsed_iv, data = self.parse_cipher_input(input_text, mode)
                if parsed_iv is not None:
                    iv = parsed_iv
                    cipher = self.get_cipher(key, iv)
                
                result = cipher.decrypt(data)
                if mode != "CTR":
                    result = unpad(result, self.get_block_size())
                output = self.format_bytes(result, self.output_format_combo.currentText())
            
            self.output_edit.setPlainText(output)
        except Exception as e:
            self.output_edit.setPlainText(f"错误: {str(e)}")
    
    def execute_xor(self):
        """执行XOR加密/解密"""
        key = self.key_edit.text()
        if not key:
            self.output_edit.setPlainText("错误: 请输入密钥")
            return
        
        input_text = self.input_edit.toPlainText()
        if not input_text:
            self.output_edit.setPlainText("请输入内容")
            return
        
        is_encrypt = self.op_combo.currentIndex() == 0
        
        try:
            key_bytes = self.parse_bytes(key, self.key_format_combo.currentText())
            
            if is_encrypt:
                plaintext_bytes = self.parse_bytes(input_text, self.input_format_combo.currentText())
                result = []
                for i, byte in enumerate(plaintext_bytes):
                    result.append(byte ^ key_bytes[i % len(key_bytes)])
                output = self.format_bytes(bytes(result), self.output_format_combo.currentText())
            else:
                try:
                    ciphertext_bytes = self.parse_bytes(input_text, self.input_format_combo.currentText())
                except:
                    self.output_edit.setPlainText("错误: 密文格式错误")
                    return
                
                result = []
                for i, byte in enumerate(ciphertext_bytes):
                    result.append(byte ^ key_bytes[i % len(key_bytes)])
                output = self.format_bytes(bytes(result), self.output_format_combo.currentText())
            
            self.output_edit.setPlainText(output)
        except Exception as e:
            self.output_edit.setPlainText(f"错误: {str(e)}")
    
    def execute_fernet(self):
        """执行Fernet加密/解密"""
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            self.output_edit.setPlainText("错误: 需要安装 cryptography 库\npip install cryptography")
            return
        
        key = self.key_edit.text()
        input_text = self.input_edit.toPlainText()
        is_encrypt = self.op_combo.currentIndex() == 0
        
        try:
            if is_encrypt:
                if not key:
                    key = Fernet.generate_key()
                    self.key_edit.setText(self.format_bytes(key, self.key_format_combo.currentText()))
                else:
                    key = self.parse_bytes(key, self.key_format_combo.currentText())
                
                f = Fernet(key)
                plaintext = self.parse_bytes(input_text, self.input_format_combo.currentText())
                ciphertext = f.encrypt(plaintext)
                self.output_edit.setPlainText(self.format_bytes(ciphertext, self.output_format_combo.currentText()))
            else:
                if not key:
                    self.output_edit.setPlainText("错误: 解密需要密钥")
                    return
                
                key = self.parse_bytes(key, self.key_format_combo.currentText())
                f = Fernet(key)
                ciphertext = self.parse_bytes(input_text, self.input_format_combo.currentText())
                plaintext = f.decrypt(ciphertext)
                self.output_edit.setPlainText(self.format_bytes(plaintext, self.output_format_combo.currentText()))
        except Exception as e:
            self.output_edit.setPlainText(f"错误: {str(e)}")
    
    def execute_rc4(self):
        """执行RC4加密/解密"""
        key = self.key_edit.text()
        if not key:
            self.output_edit.setPlainText("错误: 请输入密钥")
            return
        
        input_text = self.input_edit.toPlainText()
        if not input_text:
            self.output_edit.setPlainText("请输入内容")
            return
        
        is_encrypt = self.op_combo.currentIndex() == 0
        
        try:
            key_bytes = self.parse_bytes(key, self.key_format_combo.currentText())
            
            if is_encrypt:
                plaintext_bytes = self.parse_bytes(input_text, self.input_format_combo.currentText())
            else:
                try:
                    plaintext_bytes = self.parse_bytes(input_text, self.input_format_combo.currentText())
                except:
                    self.output_edit.setPlainText("错误: 密文格式错误")
                    return
            
            # RC4算法
            S = list(range(256))
            j = 0
            for i in range(256):
                j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
                S[i], S[j] = S[j], S[i]
            
            i = j = 0
            result = []
            for byte in plaintext_bytes:
                i = (i + 1) % 256
                j = (j + S[i]) % 256
                S[i], S[j] = S[j], S[i]
                k = S[(S[i] + S[j]) % 256]
                result.append(k ^ byte)
            
            if is_encrypt:
                output = self.format_bytes(bytes(result), self.output_format_combo.currentText())
            else:
                output = self.format_bytes(bytes(result), self.output_format_combo.currentText())
            
            self.output_edit.setPlainText(output)
        except Exception as e:
            self.output_edit.setPlainText(f"错误: {str(e)}")
    
    def copy_result(self):
        text = self.output_edit.toPlainText()
        if text:
            copy_plain_text(text)
