from pathlib import Path
from urllib.parse import unquote, urlparse

from PyQt5.QtCore import QObject, QEvent
from PyQt5.QtWidgets import QMessageBox


class TextFileDropHelper(QObject):
    """Read dropped files into text widgets using the existing panel behavior."""

    TEXT_SUFFIXES = {
        '.txt', '.json', '.csv', '.xml', '.html', '.htm', '.md', '.pem',
        '.key', '.pub', '.asc', '.log', '.ini', '.cfg'
    }

    def __init__(self, owner, target_widget, success_message='已导入内容: {path} ({mode})'):
        super().__init__(owner)
        self.owner = owner
        self.target_widget = target_widget
        self.success_message = success_message
        self._loading_file_reference = False
        self.target_widget.setAcceptDrops(True)
        self.target_widget.installEventFilter(self)
        if hasattr(self.target_widget, 'textChanged'):
            self.target_widget.textChanged.connect(self._replace_file_reference_input)

    def eventFilter(self, obj, event):
        if obj == self.target_widget:
            if event.type() == QEvent.DragEnter and event.mimeData().hasUrls():
                event.acceptProposedAction()
                return True
            if event.type() == QEvent.Drop and event.mimeData().hasUrls():
                urls = event.mimeData().urls()
                file_path = urls[0].toLocalFile() if urls else ''
                if file_path and self.load_file(file_path):
                    event.acceptProposedAction()
                    return True
        return super().eventFilter(obj, event)

    def load_file(self, file_path):
        try:
            normalized = self._normalize_file_reference(file_path) or file_path
            content, mode = self._read_file_as_text(normalized)
        except Exception as exc:
            QMessageBox.warning(self.owner, '导入失败', f'读取文件失败: {str(exc)}')
            return False
        self._loading_file_reference = True
        try:
            self._set_widget_text(content)
        finally:
            self._loading_file_reference = False
        if hasattr(self.owner, 'status_tip'):
            self.owner.status_tip(self.success_message.format(path=normalized, mode=mode))
        return True

    def _replace_file_reference_input(self):
        if self._loading_file_reference:
            return
        text = self._get_widget_text().strip()
        if not text or '\n' in text or '\r' in text:
            return
        path_text = self._normalize_file_reference(text)
        if not path_text:
            return
        try:
            if not Path(path_text).is_file():
                return
        except OSError:
            return
        self.load_file(path_text)

    def _read_file_as_text(self, file_path):
        path = Path(file_path)
        data = path.read_bytes()
        should_try_text = path.suffix.lower() in self.TEXT_SUFFIXES
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

    @staticmethod
    def _looks_like_text(text):
        if not text:
            return True
        sample = text[:4096]
        bad = sum(1 for ch in sample if ch == '\x00' or (ord(ch) < 32 and ch not in '\r\n\t'))
        return bad / max(1, len(sample)) < 0.02

    @staticmethod
    def _normalize_file_reference(value):
        text = str(value).strip().strip('"\'')
        if not text:
            return None
        if text.lower().startswith('file://'):
            parsed = urlparse(text)
            path_text = unquote(parsed.path or '')
            if parsed.netloc:
                path_text = f"//{parsed.netloc}{path_text}"
            if len(path_text) >= 3 and path_text[0] == '/' and path_text[2] == ':' and path_text[1].isalpha():
                path_text = path_text[1:]
            return path_text.replace('/', '\\')
        return text

    def _get_widget_text(self):
        if hasattr(self.target_widget, 'toPlainText'):
            return self.target_widget.toPlainText()
        if hasattr(self.target_widget, 'text'):
            return self.target_widget.text()
        return ''

    def _set_widget_text(self, text):
        if hasattr(self.target_widget, 'setPlainText'):
            self.target_widget.setPlainText(text)
            return
        if hasattr(self.target_widget, 'setText'):
            self.target_widget.setText(text)
