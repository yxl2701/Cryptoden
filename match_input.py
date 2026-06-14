"""
正则匹配模块
============
实现程序的正则匹配功能，支持正则匹配的匹配项。

功能:
- 支持默认匹配项
- 支持用户自定义匹配项
- 匹配项之间用分号隔开
- 匹配到后突出显示匹配内容
"""

import re
from typing import List, Tuple, Optional
from PyQt5.QtCore import QObject, pyqtSignal
from PyQt5.QtGui import QTextCharFormat, QColor, QTextCursor


DEFAULT_PATTERNS = ['flag', 'ctf', 'key', 'password', 'secret', 'admin', 'root']


class MatchInput:
    """
    正则匹配输入类
    
    处理用户输入的匹配模式，支持正则表达式。
    """
    
    def __init__(self, patterns: str = None, separator: str = ';'):
        """
        初始化匹配输入
        
        参数:
            patterns: 匹配模式字符串，多个模式用分隔符隔开
            separator: 分隔符，默认为分号
        """
        self.separator = separator
        self.patterns = self.parse_patterns(patterns) if patterns else DEFAULT_PATTERNS.copy()
        
    def parse_patterns(self, patterns_str: str) -> List[str]:
        """
        解析匹配模式字符串
        
        参数:
            patterns_str: 匹配模式字符串
            
        返回:
            匹配模式列表
        """
        if not patterns_str:
            return DEFAULT_PATTERNS.copy()
            
        patterns = []
        for pattern in patterns_str.split(self.separator):
            pattern = pattern.strip()
            if pattern:
                patterns.append(pattern)
                
        return patterns if patterns else DEFAULT_PATTERNS.copy()
        
    def add_pattern(self, pattern: str):
        """添加匹配模式"""
        if pattern and pattern not in self.patterns:
            self.patterns.append(pattern)
            
    def remove_pattern(self, pattern: str):
        """移除匹配模式"""
        if pattern in self.patterns:
            self.patterns.remove(pattern)
            
    def clear_patterns(self):
        """清空匹配模式"""
        self.patterns.clear()
        
    def reset_to_default(self):
        """重置为默认匹配模式"""
        self.patterns = DEFAULT_PATTERNS.copy()
        
    def match(self, text: str, case_sensitive: bool = False) -> List[Tuple[str, int, int]]:
        """
        在文本中匹配模式
        
        参数:
            text: 待匹配文本
            case_sensitive: 是否区分大小写
            
        返回:
            匹配结果列表，每个元素为 (匹配到的模式, 起始位置, 结束位置)
        """
        results = []
        search_text = text if case_sensitive else text.lower()
        
        for pattern in self.patterns:
            search_pattern = pattern if case_sensitive else pattern.lower()
            start = 0
            
            while True:
                pos = search_text.find(search_pattern, start)
                if pos == -1:
                    break
                    
                results.append((pattern, pos, pos + len(pattern)))
                start = pos + 1
                
        return sorted(results, key=lambda x: x[1])
        
    def highlight_matches(self, text_edit, bg_color: str = "#FFFF00", fg_color: str = "#FF0000",
                          case_sensitive: bool = False):
        """
        在QTextEdit中高亮显示匹配内容
        
        参数:
            text_edit: QTextEdit控件
            bg_color: 背景颜色
            fg_color: 前景颜色
            case_sensitive: 是否区分大小写
        """
        text = text_edit.toPlainText()
        matches = self.match(text, case_sensitive)
        
        cursor = text_edit.textCursor()
        
        fmt = QTextCharFormat()
        fmt.setBackground(QColor(bg_color))
        fmt.setForeground(QColor(fg_color))
        fmt.setFontWeight(75)
        
        for pattern, start, end in matches:
            cursor.setPosition(start)
            cursor.setPosition(end, QTextCursor.KeepAnchor)
            cursor.setCharFormat(fmt)
            
    def get_pattern_string(self) -> str:
        """
        获取匹配模式字符串
        
        返回:
            用分隔符连接的匹配模式字符串
        """
        return self.separator.join(self.patterns)


def match_patterns(text: str, patterns: str = None, case_sensitive: bool = False) -> List[Tuple[str, int, int]]:
    """
    匹配模式函数
    
    参数:
        text: 待匹配文本
        patterns: 匹配模式字符串
        case_sensitive: 是否区分大小写
        
    返回:
        匹配结果列表
    """
    matcher = MatchInput(patterns)
    return matcher.match(text, case_sensitive)
