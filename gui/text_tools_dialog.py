from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QApplication, QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTextEdit, QGroupBox, QSpinBox, QLineEdit, QMessageBox

from utils.text_tools import (
    decode_escaped_text,
    get_character_frequencies,
    get_text_statistics,
    remove_all_whitespace,
    remove_spaces_only,
    reverse_text,
    keep_alphanumeric,
    keep_hex_characters,
    split_text_by_length,
    url_decode_text,
)


class TextToolsDialog(QDialog):
    def __init__(self, parent=None, text=""):
        super().__init__(parent)
        self.setWindowTitle("文本工具")
        self.setMinimumSize(760, 560)
        self._result_text = text
        self._result_is_transform = False
        self._build_ui(text)

    def _build_ui(self, text):
        layout = QVBoxLayout(self)

        source_group = QGroupBox("输入")
        source_layout = QVBoxLayout(source_group)
        self.source_edit = QTextEdit()
        self.source_edit.setFont(QFont("Consolas", 10))
        self.source_edit.setPlainText(text)
        source_layout.addWidget(self.source_edit)
        layout.addWidget(source_group)

        control_row = QHBoxLayout()
        control_row.addWidget(QLabel("按长度分割:"))
        self.length_spin = QSpinBox()
        self.length_spin.setRange(1, 100000)
        self.length_spin.setValue(4)
        control_row.addWidget(self.length_spin)
        control_row.addWidget(QLabel("分隔符:"))
        self.separator_edit = QLineEdit(" ")
        control_row.addWidget(self.separator_edit, stretch=1)
        layout.addLayout(control_row)

        action_row = QHBoxLayout()
        split_btn = QPushButton("按长度分割")
        split_btn.clicked.connect(self.apply_split)
        action_row.addWidget(split_btn)

        compact_btn = QPushButton("去除空白")
        compact_btn.clicked.connect(self.apply_compact)
        action_row.addWidget(compact_btn)

        remove_spaces_btn = QPushButton("去空格")
        remove_spaces_btn.clicked.connect(self.apply_remove_spaces)
        action_row.addWidget(remove_spaces_btn)

        hex_btn = QPushButton("保留Hex")
        hex_btn.clicked.connect(self.apply_keep_hex)
        action_row.addWidget(hex_btn)

        alnum_btn = QPushButton("保留字母数字")
        alnum_btn.clicked.connect(self.apply_keep_alnum)
        action_row.addWidget(alnum_btn)

        reverse_btn = QPushButton("反转文本")
        reverse_btn.clicked.connect(self.apply_reverse)
        action_row.addWidget(reverse_btn)

        decode_escape_btn = QPushButton("转义解码")
        decode_escape_btn.clicked.connect(self.apply_decode_escape)
        action_row.addWidget(decode_escape_btn)

        url_decode_btn = QPushButton("URL解码")
        url_decode_btn.clicked.connect(self.apply_url_decode)
        action_row.addWidget(url_decode_btn)

        stats_btn = QPushButton("统计信息")
        stats_btn.clicked.connect(self.show_stats)
        action_row.addWidget(stats_btn)

        freq_btn = QPushButton("字符频率")
        freq_btn.clicked.connect(self.show_frequencies)
        action_row.addWidget(freq_btn)
        action_row.addStretch()
        layout.addLayout(action_row)

        result_group = QGroupBox("结果")
        result_layout = QVBoxLayout(result_group)
        self.result_edit = QTextEdit()
        self.result_edit.setReadOnly(True)
        self.result_edit.setFont(QFont("Consolas", 10))
        result_layout.addWidget(self.result_edit)
        layout.addWidget(result_group)

        bottom_row = QHBoxLayout()
        bottom_row.addStretch()

        apply_btn = QPushButton("应用到输入")
        apply_btn.clicked.connect(self.accept)
        bottom_row.addWidget(apply_btn)

        copy_btn = QPushButton("复制结果")
        copy_btn.clicked.connect(self.copy_result)
        bottom_row.addWidget(copy_btn)

        close_btn = QPushButton("关闭")
        close_btn.clicked.connect(self.reject)
        bottom_row.addWidget(close_btn)
        layout.addLayout(bottom_row)

    def _set_result(self, text: str):
        self._result_text = text
        self.result_edit.setPlainText(text)

    def _set_transform_result(self, text: str):
        self._result_is_transform = True
        self._set_result(text)

    def _set_analysis_result(self, text: str):
        self._result_is_transform = False
        self._set_result(text)

    def apply_split(self):
        text = self.source_edit.toPlainText()
        length = self.length_spin.value()
        separator = self.separator_edit.text()
        self._set_transform_result(split_text_by_length(text, length, separator))

    def apply_compact(self):
        text = self.source_edit.toPlainText()
        self._set_transform_result(remove_all_whitespace(text))

    def apply_remove_spaces(self):
        text = self.source_edit.toPlainText()
        self._set_transform_result(remove_spaces_only(text))

    def apply_keep_hex(self):
        text = self.source_edit.toPlainText()
        self._set_transform_result(keep_hex_characters(text))

    def apply_keep_alnum(self):
        text = self.source_edit.toPlainText()
        self._set_transform_result(keep_alphanumeric(text))

    def apply_reverse(self):
        text = self.source_edit.toPlainText()
        self._set_transform_result(reverse_text(text))

    def apply_decode_escape(self):
        text = self.source_edit.toPlainText()
        try:
            self._set_transform_result(decode_escaped_text(text))
        except UnicodeDecodeError as exc:
            QMessageBox.warning(self, "转义解码失败", str(exc))

    def apply_url_decode(self):
        text = self.source_edit.toPlainText()
        self._set_transform_result(url_decode_text(text))

    def show_stats(self):
        stats = get_text_statistics(self.source_edit.toPlainText())
        self._set_analysis_result(
            "\n".join([
                f"字符数: {stats['characters']}",
                f"非空白字符数: {stats['non_whitespace_characters']}",
                f"行数: {stats['lines']}",
                f"单词数: {stats['words']}",
                f"唯一字符数: {stats['unique_characters']}",
                f"字母数: {stats['letters']}",
                f"数字数: {stats['digits']}",
                f"空白字符数: {stats['whitespace']}",
                f"Hex字符数: {stats['hex_characters']}",
                f"疑似Hex串: {'是' if stats['is_probably_hex'] else '否'}",
            ])
        )

    def show_frequencies(self):
        frequencies = get_character_frequencies(self.source_edit.toPlainText())
        if not frequencies:
            self._set_analysis_result("无内容")
            return
        lines = []
        for ch, count in frequencies:
            label = repr(ch)[1:-1]
            if ch == ' ':
                label = '<space>'
            elif ch == '\n':
                label = '<newline>'
            elif ch == '\t':
                label = '<tab>'
            lines.append(f"{label}: {count}")
        self._set_analysis_result("\n".join(lines))

    def copy_result(self):
        text = self.result_edit.toPlainText()
        if text:
            QApplication.clipboard().setText(text)

    def result_text(self):
        return self._result_text

    def accept(self):
        if not self._result_is_transform:
            self._result_text = self.source_edit.toPlainText()
            super().accept()
            return
        text = self.result_edit.toPlainText()
        self._result_text = text if text else self.source_edit.toPlainText()
        super().accept()
