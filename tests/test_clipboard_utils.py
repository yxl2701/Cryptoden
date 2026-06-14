import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

from PyQt5.QtCore import QEvent, Qt
from PyQt5.QtGui import QKeyEvent
from PyQt5.QtWidgets import QApplication, QTextEdit, QWidget


MODULE_PATH = Path(__file__).parent.parent / "gui" / "clipboard_utils.py"
SPEC = spec_from_file_location("test_clipboard_utils_module", MODULE_PATH)
CLIPBOARD_UTILS = module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(CLIPBOARD_UTILS)
install_plain_text_copy = CLIPBOARD_UTILS.install_plain_text_copy


def _get_app():
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    return app


class _FakeClipboard:
    def __init__(self, text):
        self._text = text

    def text(self):
        return self._text


class _FakeApplication:
    def __init__(self, clipboard):
        self._clipboard = clipboard

    def clipboard(self):
        return self._clipboard


def test_paste_uses_plain_text_only(monkeypatch):
    app = _get_app()
    container = QWidget()
    editor = QTextEdit(container)
    install_plain_text_copy(container)

    monkeypatch.setattr(CLIPBOARD_UTILS, "QApplication", _FakeApplication(_FakeClipboard('styled text')))

    paste_event = QKeyEvent(QEvent.KeyPress, Qt.Key_V, Qt.ControlModifier)
    QApplication.sendEvent(editor, paste_event)

    assert editor.toPlainText() == 'styled text'
    html = editor.toHtml().lower()
    assert '24pt' not in html
    assert 'color:red' not in html
    assert '#ff0000' not in html
