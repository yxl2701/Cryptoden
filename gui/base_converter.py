"""
进制转换对话框模块
=================
提供进制转换功能的图形界面
"""

from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                             QLineEdit, QComboBox, QPushButton, QGroupBox)
from PyQt5.QtCore import Qt


class BaseConverterDialog(QDialog):
    """
    进制转换对话框类
    
    提供多种进制之间的转换功能，支持：
    - 2进制 (Binary)
    - 8进制 (Octal)
    - 10进制 (Decimal)
    - 16进制 (Hexadecimal)
    
    输入数值并设置输入进制后，同时显示所有进制的转换结果。
    
    属性:
        input_edit: 输入文本框
        base_combo: 进制选择下拉框
        output_labels: 各进制输出标签字典
    """
    
    def __init__(self, parent=None):
        """
        初始化进制转换对话框
        
        参数:
            parent: 父窗口引用
        """
        super().__init__(parent)
        self.setWindowTitle("进制转换")
        self.setMinimumSize(500, 380)
        self.setup_ui()
    
    def setup_ui(self):
        """构建对话框界面"""
        layout = QVBoxLayout()
        
        # 输入区域
        input_group = QGroupBox("输入")
        input_layout = QVBoxLayout()
        
        input_layout.addWidget(QLabel("输入进制:"))
        
        self.base_combo = QComboBox()
        self.base_combo.addItems([
            "2进制 (Binary)", 
            "8进制 (Octal)", 
            "10进制 (Decimal)", 
            "16进制 (Hexadecimal)"
        ])
        self.base_combo.currentIndexChanged.connect(self.convert)
        input_layout.addWidget(self.base_combo)
        
        input_layout.addWidget(QLabel("输入数值:"))
        
        self.input_edit = QLineEdit()
        self.input_edit.setPlaceholderText("请输入需要转换的数值")
        self.input_edit.textChanged.connect(self.convert)
        input_layout.addWidget(self.input_edit)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # 输出区域 - 显示所有进制（每个一行）
        output_group = QGroupBox("输出 (所有进制)")
        output_layout = QVBoxLayout()
        
        base_names = [
            ("2进制", "BIN"),
            ("8进制", "OCT"),
            ("10进制", "DEC"),
            ("16进制", "HEX")
        ]
        
        self.output_labels = {}
        
        for name, key in base_names:
            row_layout = QHBoxLayout()
            
            label = QLabel(f"{name}:")
            label.setFixedWidth(80)
            label.setStyleSheet("font-weight: bold;")
            row_layout.addWidget(label)
            
            value_label = QLabel("")
            value_label.setStyleSheet("background-color: #f0f0f0; padding: 5px; border: 1px solid #ccc;")
            value_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            row_layout.addWidget(value_label)
            
            output_layout.addLayout(row_layout)
            self.output_labels[key] = value_label
        
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        # 按钮区域
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        clear_btn = QPushButton("清空")
        clear_btn.clicked.connect(self.clear_all)
        button_layout.addWidget(clear_btn)
        
        close_btn = QPushButton("关闭")
        close_btn.clicked.connect(self.close)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def get_base_value(self, index):
        """
        根据下拉框索引获取进制的原始值
        
        参数:
            index: 下拉框索引
            
        返回:
            int: 进制值 (2, 8, 10, 16)
        """
        bases = [2, 8, 10, 16]
        return bases[index]
    
    def convert(self):
        """执行进制转换，显示所有进制的结果"""
        input_text = self.input_edit.text().strip()
        
        for label in self.output_labels.values():
            label.setText("")
            label.setStyleSheet("background-color: #f0f0f0; padding: 5px; border: 1px solid #ccc;")
        
        if not input_text:
            return
        
        input_base = self.get_base_value(self.base_combo.currentIndex())
        
        try:
            result = int(input_text, input_base)
            
            self.output_labels["BIN"].setText(bin(result)[2:])
            self.output_labels["OCT"].setText(oct(result)[2:])
            self.output_labels["DEC"].setText(str(result))
            self.output_labels["HEX"].setText(hex(result)[2:].upper())
            
        except (ValueError, Exception) as e:
            error_style = "background-color: #ffe0e0; padding: 5px; border: 1px solid #ff6666; color: #cc0000;"
            for label in self.output_labels.values():
                label.setText("转换错误")
                label.setStyleSheet(error_style)
    
    def clear_all(self):
        """清空输入和所有输出"""
        self.input_edit.clear()
        for label in self.output_labels.values():
            label.setText("")
