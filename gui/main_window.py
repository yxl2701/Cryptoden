"""
主窗口模块 (Main Window)
========================
CTF加解密工具的主界面实现

本模块包含:
- CryptoTool类: 主窗口类，使用QTabWidget整合加解密面板和AI面板
"""

import sys
import json
from pathlib import Path
from cryptoden import __version__

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QMenu, QAction, QLabel, QPushButton,
    QTextEdit, QMessageBox,
    QFileDialog, QApplication, QComboBox,
    QLineEdit, QDialog, QListWidget,
    QTabWidget
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon

from core.constants import CATEGORY_NAMES
from .settings_dialog import SettingsDialog
from .base_converter import BaseConverterDialog
from .rsa_dialog import RSADialog
from .ecc_dialog import ECCDialog
from .lcg_dialog import LCGDialog
from .symmetric_dialog import SymmetricDialog
from .ai_workspace_panel import AIWorkspacePanel
from .crypto_panel import CryptoPanel
from .algorithm_tabs import load_algorithm_tab_defs
from utils.recursive_config import load_recursive_config


class CryptoTool(QMainWindow):
    """
    CTF加解密工具主窗口类
    使用QTabWidget整合加解密面板和AI面板
    """
    
    def __init__(self):
        super().__init__()
        self.config_path = Path(__file__).parent.parent / "config.json"
        self.base_path = Path(__file__).parent.parent
        self.app_config = self.load_settings()
        self.algorithm_tab_defs = load_algorithm_tab_defs(self.base_path)
        
        self.menu_bg_color = self.app_config.get("menu_bg_color", "#FFFFFF")
        self.menu_text_color = self.app_config.get("menu_text_color", "#333333")
        self.menu_hover_bg = self.app_config.get("menu_hover_bg", "#E3F2FD")
        self.menu_selected_bg = self.app_config.get("menu_selected_bg", "#BBDEFB")
        self.status_bg_color = self.app_config.get("status_bg_color", "#F0F0F0")
        
        self.init_ui()
        self.apply_colors()
        self.apply_saved_panel_settings()
    
    def load_settings(self):
        try:
            if self.config_path.exists():
                return json.loads(self.config_path.read_text(encoding="utf-8"))
        except Exception:
            pass
        return {}
    
    def save_settings(self):
        if hasattr(self, 'crypto_panel'):
            panel = self.crypto_panel
            recursive_config = dict(self.app_config.get("recursive_decrypt", {}))
            recursive_config.update({
                "max_depth": panel.recursive_max_depth,
                "max_workers": panel.recursive_max_workers,
                "max_tasks": panel.recursive_max_tasks,
                "max_display_results": panel.recursive_max_display_results,
                "brute_force_small_keyspaces": panel.recursive_bruteforce,
                "custom_features": panel.recursive_custom_features,
                "disabled_builtin_features": panel.recursive_disabled_builtin_features,
            })
            self.app_config.update({
                "auto_copy": panel.auto_copy,
                "auto_swap": panel.auto_swap,
                "input_bg_color": panel.input_bg_color,
                "output_bg_color": panel.output_bg_color,
                "param_bg_color": panel.param_bg_color,
                "font_family": panel.input_text.font().family(),
                "font_size": panel.input_text.font().pointSize(),
                "recursive_decrypt": recursive_config,
            })
        self.app_config.update({
            "menu_bg_color": self.menu_bg_color,
            "menu_text_color": self.menu_text_color,
            "menu_hover_bg": self.menu_hover_bg,
            "menu_selected_bg": self.menu_selected_bg,
            "status_bg_color": self.status_bg_color,
        })
        self.config_path.write_text(json.dumps(self.app_config, ensure_ascii=False, indent=2), encoding="utf-8")
    
    def apply_saved_panel_settings(self):
        panels = self._all_crypto_panels()
        if not panels:
            return
        self.auto_copy_action.setChecked(bool(self.app_config.get("auto_copy", False)))
        self.auto_swap_action.setChecked(bool(self.app_config.get("auto_swap", False)))
        default_recursive_config = load_recursive_config(self.base_path)
        recursive_config = self.app_config.get("recursive_decrypt", {})
        font_family = self.app_config.get("font_family")
        font_size = self.app_config.get("font_size")

        for panel in panels:
            panel.auto_copy = self.auto_copy_action.isChecked()
            panel.auto_swap = self.auto_swap_action.isChecked()
            panel.input_bg_color = self.app_config.get("input_bg_color", panel.input_bg_color)
            panel.output_bg_color = self.app_config.get("output_bg_color", panel.output_bg_color)
            panel.param_bg_color = self.app_config.get("param_bg_color", panel.param_bg_color)
            if isinstance(recursive_config, dict):
                panel.recursive_max_depth = int(recursive_config.get("max_depth", panel.recursive_max_depth))
                panel.recursive_max_workers = int(recursive_config.get("max_workers", panel.recursive_max_workers))
                panel.recursive_max_tasks = int(recursive_config.get("max_tasks", panel.recursive_max_tasks))
                panel.recursive_max_display_results = min(
                    int(recursive_config.get("max_display_results", panel.recursive_max_display_results)),
                    1000,
                )
                panel.recursive_bruteforce = bool(recursive_config.get("brute_force_small_keyspaces", panel.recursive_bruteforce))
                custom_features = recursive_config.get(
                    "custom_features",
                    default_recursive_config.get("custom_features", panel.recursive_custom_features),
                )
                panel.recursive_custom_features = custom_features if isinstance(custom_features, list) else []
                disabled_features = recursive_config.get(
                    "disabled_builtin_features",
                    default_recursive_config.get("disabled_builtin_features", panel.recursive_disabled_builtin_features),
                )
                panel.recursive_disabled_builtin_features = disabled_features if isinstance(disabled_features, list) else []
            if font_family or font_size:
                font = panel.input_text.font()
                if font_family:
                    font.setFamily(font_family)
                if font_size:
                    font.setPointSize(int(font_size))
                panel.input_text.setFont(font)
                panel.output_text.setFont(font)
            panel.apply_colors()
    
    def init_ui(self):
        self.setWindowTitle("Cryptoden - CTF加解密工具")
        icon_path = Path(__file__).parent.parent / "cryptoden_icon.png"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))
        self.resize(1500, 950)
        self._center_window()
        
        self.create_menubar()
        self.create_central()
        self.create_statusbar()
    
    def create_menubar(self):
        menubar = self.menuBar()
        
        # 文件菜单
        file_menu = menubar.addMenu("文件(&F)")
        
        open_action = QAction("打开文件...", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self.open_file)
        file_menu.addAction(open_action)
        
        save_action = QAction("保存结果...", self)
        save_action.setShortcut("Ctrl+Shift+S")
        save_action.triggered.connect(self.save_file)
        file_menu.addAction(save_action)
        
        file_menu.addSeparator()
        
        refresh_action = QAction("刷新算法列表", self)
        refresh_action.setShortcut("F5")
        refresh_action.triggered.connect(self.refresh_modules)
        file_menu.addAction(refresh_action)
        
        file_menu.addSeparator()
        
        restart_action = QAction("重启程序", self)
        restart_action.setShortcut("Ctrl+R")
        restart_action.setStatusTip("重新启动程序")
        restart_action.triggered.connect(self.restart_app)
        file_menu.addAction(restart_action)
        
        exit_action = QAction("退出", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # 编辑菜单
        edit_menu = menubar.addMenu("编辑(&E)")
        
        self.undo_action = QAction("撤销", self)
        self.undo_action.setShortcut("Ctrl+Z")
        self.undo_action.triggered.connect(self.undo_input)
        self.undo_action.setEnabled(False)
        edit_menu.addAction(self.undo_action)
        
        self.redo_action = QAction("重做", self)
        self.redo_action.setShortcut("Ctrl+Y")
        self.redo_action.triggered.connect(self.redo_input)
        self.redo_action.setEnabled(False)
        edit_menu.addAction(self.redo_action)
        
        edit_menu.addSeparator()
        
        paste_action = QAction("粘贴", self)
        paste_action.setShortcut("Ctrl+V")
        paste_action.triggered.connect(self.paste_input)
        edit_menu.addAction(paste_action)
        
        edit_menu.addSeparator()
        
        clear_all_action = QAction("清空全部", self)
        clear_all_action.setShortcut("Ctrl+Delete")
        clear_all_action.triggered.connect(self.clear_all)
        edit_menu.addAction(clear_all_action)
        
        # 加密/解密菜单
        self.encrypt_menu = menubar.addMenu("加密(&X)")
        self.decrypt_menu = menubar.addMenu("解密(&D)")
        
        # 对称密码菜单
        symmetric_menu = menubar.addMenu("对称密码(&S)")
        
        symmetric_action = QAction("AES/DES/3DES/Blowfish/RC4...", self)
        symmetric_action.triggered.connect(self.show_symmetric_dialog)
        symmetric_menu.addAction(symmetric_action)
        
        # 非对称密码菜单
        asymmetric_menu = menubar.addMenu("非对称密码(&A)")
        
        rsa_action = QAction("RSA", self)
        rsa_action.triggered.connect(self.show_rsa_dialog)
        asymmetric_menu.addAction(rsa_action)
        
        ecc_action = QAction("ECC", self)
        ecc_action.triggered.connect(self.show_ecc_dialog)
        asymmetric_menu.addAction(ecc_action)
        
        lcg_action = QAction("LCG", self)
        lcg_action.triggered.connect(self.show_lcg_dialog)
        asymmetric_menu.addAction(lcg_action)
        
        # 转换菜单
        transform_menu = menubar.addMenu("转换(&T)")
        
        case_menu = transform_menu.addMenu("大小写转换")
        upper_action = QAction("转为大写", self)
        upper_action.setShortcut("Ctrl+U")
        upper_action.triggered.connect(self.to_upper)
        case_menu.addAction(upper_action)
        lower_action = QAction("转为小写", self)
        lower_action.setShortcut("Ctrl+L")
        lower_action.triggered.connect(self.to_lower)
        case_menu.addAction(lower_action)
        
        format_menu = transform_menu.addMenu("格式处理")
        strip_action = QAction("去除首尾空白", self)
        strip_action.triggered.connect(self.strip_text)
        format_menu.addAction(strip_action)
        remove_space_action = QAction("移除所有空格", self)
        remove_space_action.triggered.connect(self.remove_spaces)
        format_menu.addAction(remove_space_action)
        remove_line_action = QAction("移除所有换行", self)
        remove_line_action.triggered.connect(self.remove_lines)
        format_menu.addAction(remove_line_action)
        
        transform_menu.addSeparator()
        
        base_convert_action = QAction("进制转换", self)
        base_convert_action.triggered.connect(self.show_base_converter)
        transform_menu.addAction(base_convert_action)
        
        transform_menu.addSeparator()
        
        reverse_action = QAction("反转文本", self)
        reverse_action.triggered.connect(self.reverse_text)
        transform_menu.addAction(reverse_action)
        
        # 设置菜单
        settings_menu = menubar.addMenu("设置(&S)")
        
        settings_action = QAction("首选项...", self)
        settings_action.triggered.connect(self.show_settings)
        settings_menu.addAction(settings_action)
        
        settings_menu.addSeparator()
        
        self.auto_copy_action = QAction("自动复制结果", self)
        self.auto_copy_action.setCheckable(True)
        self.auto_copy_action.setChecked(False)
        self.auto_copy_action.triggered.connect(self.toggle_auto_copy)
        settings_menu.addAction(self.auto_copy_action)
        
        self.auto_swap_action = QAction("自动交换", self)
        self.auto_swap_action.setCheckable(True)
        self.auto_swap_action.setChecked(False)
        self.auto_swap_action.triggered.connect(self.toggle_auto_swap)
        settings_menu.addAction(self.auto_swap_action)
        
        settings_menu.addSeparator()
        
        records_action = QAction("查看解密记录", self)
        records_action.triggered.connect(self.show_decrypt_records)
        settings_menu.addAction(records_action)
        
        clear_records_action = QAction("清空解密记录", self)
        clear_records_action.triggered.connect(self.clear_decrypt_records)
        settings_menu.addAction(clear_records_action)
        
        # 帮助菜单
        help_menu = menubar.addMenu("帮助(&H)")
        
        shortcuts_action = QAction("快捷键参考", self)
        shortcuts_action.triggered.connect(self.show_shortcuts)
        help_menu.addAction(shortcuts_action)
        
        algo_list_action = QAction("算法列表", self)
        algo_list_action.triggered.connect(self.show_algo_list)
        help_menu.addAction(algo_list_action)
        
        help_menu.addSeparator()
        
        about_action = QAction("关于", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def create_central(self):
        """创建中央部件 - 使用QTabWidget整合两个面板"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        # 创建选项卡部件
        self.tab_widget = QTabWidget()
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: none;
                background-color: #f5f5f5;
            }
            QTabBar::tab {
                background-color: #E0E0E0;
                border: 1px solid #BDBDBD;
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                padding: 12px 20px 8px 20px;
                margin-right: 2px;
                margin-top: 10px;
                font-size: 10pt;
                color: #555;
                min-width: 140px;
            }
            QTabBar::tab:selected {
                background-color: #FFFFFF;
                color: #1976D2;
                border-bottom: 2px solid #1976D2;
            }
            QTabBar::tab:hover:!selected {
                background-color: #F5F5F5;
                color: #333;
            }
        """)
        
        # 创建加密/解密面板
        self.encrypt_panel = CryptoPanel(main_window=self, panel_mode='encrypt')
        self.decrypt_panel = CryptoPanel(main_window=self, panel_mode='decrypt')
        self.crypto_panel = self.decrypt_panel
        self.tab_widget.addTab(self.encrypt_panel, "加密")
        self.tab_widget.addTab(self.decrypt_panel, "解密")
        
        # 创建AI工作台面板
        self.ai_panel = AIWorkspacePanel(self)
        self.tab_widget.addTab(self.ai_panel, "AI工作台")
        
        main_layout.addWidget(self.tab_widget)
        
        # 加载算法菜单
        self.load_all_modules()
        
        # 动态创建算法选项卡
        self.create_algorithm_tabs()
    
    def _center_window(self):
        """将窗口居中显示"""
        screen = QApplication.primaryScreen().geometry()
        x = (screen.width() - self.width()) // 2
        y = (screen.height() - self.height()) // 2
        self.move(x, y)
    
    def create_statusbar(self):
        self.statusBar().showMessage("就绪 | F1 帮助 | 从菜单选择算法")
        
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("padding: 0 10px; color: #666;")
        self.statusBar().addPermanentWidget(self.status_label)
        
        for panel in self._all_crypto_panels():
            panel.input_text.selectionChanged.connect(self.update_cursor_status)
    
    def update_cursor_status(self):
        """更新光标状态显示"""
        self._current_crypto_panel().update_cursor_status()

    def _all_crypto_panels(self):
        return [panel for panel in (getattr(self, 'encrypt_panel', None), getattr(self, 'decrypt_panel', None)) if panel]

    def _current_crypto_panel(self):
        widget = self.tab_widget.currentWidget() if hasattr(self, 'tab_widget') else None
        if widget in self._all_crypto_panels():
            return widget
        return self.crypto_panel
    
    def show_settings(self):
        dialog = SettingsDialog(self)
        dialog.exec_()
        source = self.crypto_panel
        for panel in self._all_crypto_panels():
            if panel is source:
                continue
            panel.auto_copy = source.auto_copy
            panel.auto_swap = source.auto_swap
            panel.input_bg_color = source.input_bg_color
            panel.output_bg_color = source.output_bg_color
            panel.param_bg_color = source.param_bg_color
            panel.recursive_max_depth = source.recursive_max_depth
            panel.recursive_max_workers = source.recursive_max_workers
            panel.recursive_max_tasks = source.recursive_max_tasks
            panel.recursive_max_display_results = source.recursive_max_display_results
            panel.recursive_bruteforce = source.recursive_bruteforce
            panel.recursive_disabled_builtin_features = source.recursive_disabled_builtin_features
            panel.recursive_custom_features = source.recursive_custom_features
            panel.async_decryptor = None
            panel.input_text.setFont(source.input_text.font())
            panel.output_text.setFont(source.output_text.font())
            panel.apply_colors()
    
    def show_base_converter(self):
        dialog = BaseConverterDialog(self)
        dialog.show()
    
    def show_rsa_dialog(self):
        dialog = RSADialog(self)
        dialog.show()
    
    def show_ecc_dialog(self):
        dialog = ECCDialog(self)
        dialog.show()
    
    def show_lcg_dialog(self):
        dialog = LCGDialog(self)
        dialog.show()
    
    def show_symmetric_dialog(self):
        dialog = SymmetricDialog(self)
        dialog.show()
    
    def create_algorithm_tabs(self):
        enabled = self.app_config.get("enabled_algorithm_tabs", {})
        for defn in self.algorithm_tab_defs:
            default_enabled = bool(defn.get("enabled", True))
            if enabled.get(defn["name"], default_enabled):
                self._add_algorithm_tab(defn)
    
    def _add_algorithm_tab(self, defn):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 0, 0, 0)

        tab_type = defn.get("type")
        if tab_type == "symmetric":
            algo = defn.get("algorithm", defn["name"])
            dialog = SymmetricDialog(tab, initial_algorithm=algo)
        elif tab_type == "rsa":
            dialog = RSADialog(tab)
        elif tab_type == "ecc":
            dialog = ECCDialog(tab)
        elif tab_type == "lcg":
            dialog = LCGDialog(tab)
        else:
            return

        dialog.setParent(tab)
        dialog.setWindowFlags(Qt.Widget)

        for btn in dialog.findChildren(QPushButton):
            text = btn.text().strip()
            if text in ('关闭', 'Close', '取消', 'Cancel'):
                btn.hide()

        layout.addWidget(dialog)
        dialog.show()
        self.tab_widget.addTab(tab, defn["name"])

    def _show_symmetric(self, algo_name):
        if not hasattr(self, '_symmetric_dialogs'):
            self._symmetric_dialogs = {}
        if algo_name not in self._symmetric_dialogs:
            dialog = SymmetricDialog(self, initial_algorithm=algo_name)
            self._symmetric_dialogs[algo_name] = dialog
        self._symmetric_dialogs[algo_name].show()
        self._symmetric_dialogs[algo_name].raise_()
        self._symmetric_dialogs[algo_name].activateWindow()

    def _remove_algorithm_tabs(self):
        for i in range(self.tab_widget.count() - 1, 2, -1):
            self.tab_widget.removeTab(i)

    def refresh_algorithm_tabs(self):
        self._remove_algorithm_tabs()
        self.create_algorithm_tabs()

    def toggle_auto_copy(self):
        for panel in self._all_crypto_panels():
            panel.auto_copy = self.auto_copy_action.isChecked()
        self.save_settings()
    
    def toggle_auto_swap(self):
        for panel in self._all_crypto_panels():
            panel.auto_swap = self.auto_swap_action.isChecked()
        self.save_settings()
    
    def open_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "打开文件", "", "All Files (*)")
        if file_path:
            try:
                panel = self._current_crypto_panel()
                content, mode = panel._read_file_as_panel_text(file_path)
                panel.input_text.setPlainText(content)
                self.statusBar().showMessage(f"已打开: {file_path} ({mode})")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"打开文件失败: {str(e)}")
    
    def save_file(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "保存结果", "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self._current_crypto_panel().output_text.toPlainText())
                self.statusBar().showMessage(f"已保存: {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"保存文件失败: {str(e)}")
    
    def paste_input(self):
        self._current_crypto_panel().paste_input()
    
    def clear_all(self):
        self._current_crypto_panel().clear_all()
    
    def to_upper(self):
        self._current_crypto_panel().to_upper()
    
    def to_lower(self):
        self._current_crypto_panel().to_lower()
    
    def strip_text(self):
        self._current_crypto_panel().strip_text()
    
    def remove_spaces(self):
        self._current_crypto_panel().remove_spaces()
    
    def remove_lines(self):
        self._current_crypto_panel().remove_lines()
    
    def reverse_text(self):
        self._current_crypto_panel().reverse_text()
    
    def undo_input(self):
        self._current_crypto_panel().undo_input()
    
    def redo_input(self):
        self._current_crypto_panel().redo_input()
    
    def refresh_modules(self):
        """刷新算法列表"""
        self.load_all_modules()
        self.statusBar().showMessage("算法列表已刷新")
    
    def load_all_modules(self):
        """加载所有算法到菜单（使用 CryptoLoader）"""
        self.encrypt_menu.clear()
        self.decrypt_menu.clear()
        
        # 先加载算法
        for panel in self._all_crypto_panels():
            panel.load_all_modules()
        
        # 按分类组织菜单
        standalone_categories = {'symmetric', 'asymmetric'}
        categories = [
            category for category in self.crypto_panel.crypto_loader.get_categories()
            if category not in standalone_categories
        ]
        
        for category in categories:
            cat_name = CATEGORY_NAMES.get(category, category)
            
            # 加密菜单
            encrypt_cat_menu = self.encrypt_menu.addMenu(cat_name)
            encrypt_items = sorted([
                (info['name'], info['desc'])
                for name, info in self.crypto_panel.crypto_loader.encrypt_modules.items()
                if info['category'] == category
            ], key=lambda x: x[0])
            for algo_name, desc in encrypt_items:
                action = QAction(algo_name, self)
                action.setStatusTip(desc)
                action.triggered.connect(lambda checked, n=algo_name: self.select_encrypt_algo(n))
                encrypt_cat_menu.addAction(action)
            
            # 解密菜单
            decrypt_cat_menu = self.decrypt_menu.addMenu(cat_name)
            decrypt_items = sorted([
                (info['name'], info['desc'])
                for name, info in self.crypto_panel.crypto_loader.decrypt_modules.items()
                if info['category'] == category
            ], key=lambda x: x[0])
            for algo_name, desc in decrypt_items:
                action = QAction(algo_name, self)
                action.setStatusTip(desc)
                action.triggered.connect(lambda checked, n=algo_name: self.select_decrypt_algo(n))
                decrypt_cat_menu.addAction(action)
        
        self.statusBar().showMessage(f"已加载 {len(self.crypto_panel.encrypt_modules)} 个加密算法, {len(self.crypto_panel.decrypt_modules)} 个解密算法")
    
    def select_encrypt_algo(self, algo_name):
        """选择加密算法"""
        self.tab_widget.setCurrentWidget(self.encrypt_panel)
        self.encrypt_panel.select_encrypt_algo(algo_name)
    
    def select_decrypt_algo(self, algo_name):
        """选择解密算法"""
        self.tab_widget.setCurrentWidget(self.decrypt_panel)
        self.decrypt_panel.select_decrypt_algo(algo_name)
    
    def show_decrypt_records(self):
        """显示解密记录"""
        self.crypto_panel.show_decrypt_records()
    
    def clear_decrypt_records(self):
        """清空解密记录"""
        self.crypto_panel.clear_decrypt_records()
    
    def apply_colors(self):
        self.setStyleSheet(f"""
            QMainWindow {{
                background-color: {self.menu_bg_color};
            }}
            QMenuBar {{
                background-color: {self.menu_bg_color};
                color: {self.menu_text_color};
            }}
            QMenuBar::item {{
                padding: 5px 10px;
                background-color: transparent;
            }}
            QMenuBar::item:selected {{
                background-color: {self.menu_selected_bg};
                border-radius: 3px;
            }}
            QMenu {{
                background-color: {self.menu_bg_color};
                color: {self.menu_text_color};
                border: 1px solid #ccc;
            }}
            QMenu::item {{
                padding: 5px 30px;
                border-radius: 3px;
            }}
            QMenu::item:selected {{
                background-color: {self.menu_hover_bg};
            }}
            QStatusBar {{
                background-color: {self.status_bg_color};
            }}
            QPushButton {{
                background-color: #f0f0f0;
                border: 1px solid #ccc;
                border-radius: 4px;
                padding: 4px 12px;
                color: #333;
            }}
            QPushButton:hover {{
                background-color: #e0e0e0;
                border-color: #999;
            }}
            QPushButton:pressed {{
                background-color: #d0d0d0;
            }}
        """)
    
    def show_shortcuts(self):
        QMessageBox.information(
            self, "快捷键参考",
            "常用快捷键\n\n"
            "文件：Ctrl+O 打开，Ctrl+Shift+S 保存，F5 刷新算法\n"
            "编辑：Ctrl+Z 撤销，Ctrl+Y 重做，Ctrl+V 粘贴\n"
            "清理：Ctrl+Delete 清空全部\n"
            "转换：Ctrl+U 转大写，Ctrl+L 转小写\n"
            "其他：Ctrl+Q 退出，Ctrl+R 重启"
        )
    
    def show_algo_list(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("算法列表")
        dialog.resize(720, 560)

        layout = QVBoxLayout(dialog)
        summary = QLabel(
            f"已加载 {len(self.crypto_panel.encrypt_modules)} 个加密算法，"
            f"{len(self.crypto_panel.decrypt_modules)} 个解密算法。可搜索或按分类筛选。"
        )
        summary.setStyleSheet("font-size: 10pt; color: #555; padding: 4px;")
        layout.addWidget(summary)

        filter_row = QHBoxLayout()
        mode_combo = QComboBox()
        mode_combo.addItem("加密算法", "encrypt")
        mode_combo.addItem("解密算法", "decrypt")
        filter_row.addWidget(mode_combo)

        category_combo = QComboBox()
        filter_row.addWidget(category_combo)

        search_input = QLineEdit()
        search_input.setPlaceholderText("搜索算法名，例如 base、rot、rsa...")
        filter_row.addWidget(search_input, stretch=1)
        layout.addLayout(filter_row)

        list_widget = QListWidget()
        list_widget.setStyleSheet("font-family: Consolas, Microsoft YaHei; font-size: 10pt;")
        layout.addWidget(list_widget, stretch=1)

        close_btn = QPushButton("关闭")
        close_btn.clicked.connect(dialog.accept)
        layout.addWidget(close_btn)

        def current_modules():
            mode = mode_combo.currentData()
            if mode == 'encrypt':
                return self.crypto_panel.crypto_loader.encrypt_modules
            return self.crypto_panel.crypto_loader.decrypt_modules

        def module_meta(info):
            if isinstance(info, dict):
                return {
                    'category': info.get('category', 'other'),
                    'desc': info.get('desc', '') or '',
                    'name': info.get('name', ''),
                }

            return {
                'category': getattr(info, 'category', 'other'),
                'desc': getattr(info, 'ALGORITHM_DESC', '') or '',
                'name': getattr(info, 'ALGORITHM_NAME', ''),
            }

        def refresh_categories():
            current = category_combo.currentData()
            category_combo.blockSignals(True)
            category_combo.clear()
            category_combo.addItem("全部分类", "")
            hidden_categories = {'symmetric', 'asymmetric'}
            categories = sorted({
                module_meta(info)['category'] for info in current_modules().values()
                if module_meta(info)['category'] not in hidden_categories
            })
            for category in categories:
                category_combo.addItem(CATEGORY_NAMES.get(category, category), category)
            if current:
                idx = category_combo.findData(current)
                if idx >= 0:
                    category_combo.setCurrentIndex(idx)
            category_combo.blockSignals(False)

        def refresh_list():
            modules = current_modules()
            category = category_combo.currentData() or ""
            keyword = search_input.text().strip().lower()
            list_widget.clear()

            rows = []
            hidden_categories = {'symmetric', 'asymmetric'}
            for name, info in modules.items():
                meta = module_meta(info)
                cat = meta['category']
                if cat in hidden_categories:
                    continue
                if category and cat != category:
                    continue
                desc = meta['desc']
                display_name = meta['name'] or name
                haystack = f"{display_name} {desc} {CATEGORY_NAMES.get(cat, cat)}".lower()
                if keyword and keyword not in haystack:
                    continue
                rows.append((CATEGORY_NAMES.get(cat, cat), display_name, desc))

            for cat_name, name, desc in sorted(rows, key=lambda item: (item[0], item[1])):
                suffix = f" - {desc}" if desc else ""
                list_widget.addItem(f"[{cat_name}] {name}{suffix}")

            if not rows:
                list_widget.addItem("没有匹配的算法")
            summary.setText(
                f"当前显示 {len(rows)} 个算法。"
                f"总计：加密 {len(self.crypto_panel.encrypt_modules)}，解密 {len(self.crypto_panel.decrypt_modules)}。"
            )

        def on_mode_changed():
            refresh_categories()
            refresh_list()

        mode_combo.currentIndexChanged.connect(on_mode_changed)
        category_combo.currentIndexChanged.connect(refresh_list)
        search_input.textChanged.connect(refresh_list)

        refresh_categories()
        refresh_list()
        dialog.exec_()
    
    def show_about(self):
        QMessageBox.about(
            self, "关于 Cryptoden",
            "<h2>Cryptoden</h2>"
            f"<p>版本 {__version__}</p>"
            "<p>面向 CTF 密码学题目的加解密工具箱</p>"
            "<hr>"
            "<p><b>主要功能</b></p>"
            "<ul>"
            "<li>古典密码、编码、哈希、对称/非对称密码</li>"
            "<li>一键解密、递归解密、关键字匹配与输出搜索</li>"
            "<li>RSA/ECC/LCG 攻击辅助</li>"
            "<li>AI 分析与对话，可配置 OpenAI 兼容接口</li>"
            "<li>动态加载算法，便于自行扩展</li>"
            "</ul>"
        )
    
    def restart_app(self):
        import os
        import sys
        python = sys.executable
        os.execl(python, python, *sys.argv)
