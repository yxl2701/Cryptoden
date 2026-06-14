from PyQt5.QtCore import QObject, QEvent
from PyQt5.QtGui import QKeySequence
from PyQt5.QtWidgets import QApplication, QAction, QMenu, QTextBrowser, QTextEdit


def copy_plain_text(text):
    if not text:
        return
    try:
        QApplication.clipboard().setText(text)
    except Exception:
        pass


class PlainTextCopyFilter(QObject):
    def eventFilter(self, obj, event):
        if isinstance(obj, (QTextEdit, QTextBrowser)):
            if event.type() == QEvent.KeyPress and event.matches(QKeySequence.Copy):
                self._copy_selection(obj)
                return True
            if event.type() == QEvent.KeyPress and event.matches(QKeySequence.Paste):
                self._paste_plain_text(obj)
                return True
            if event.type() == QEvent.ContextMenu:
                self._show_context_menu(obj, event.globalPos())
                return True
        return super().eventFilter(obj, event)

    def _copy_selection(self, text_edit):
        cursor = text_edit.textCursor()
        if not cursor.hasSelection():
            return
        text = cursor.selectedText().replace('\u2029', '\n').replace('\u2028', '\n')
        copy_plain_text(text)

    def _show_context_menu(self, text_edit, pos):
        menu = QMenu(text_edit)

        copy_action = QAction("复制", menu)
        copy_action.setEnabled(bool(text_edit.textCursor().selectedText()))
        copy_action.triggered.connect(lambda: self._copy_selection(text_edit))
        menu.addAction(copy_action)

        select_all_action = QAction("全选", menu)
        select_all_action.triggered.connect(text_edit.selectAll)
        menu.addAction(select_all_action)

        if not text_edit.isReadOnly():
            paste_action = QAction("粘贴", menu)
            paste_action.triggered.connect(lambda: self._paste_plain_text(text_edit))
            menu.addAction(paste_action)

        menu.exec_(pos)

    def _paste_plain_text(self, text_edit):
        if text_edit.isReadOnly():
            return
        text = QApplication.clipboard().text()
        if text:
            text_edit.insertPlainText(text)


def install_plain_text_copy(widget):
    filters = getattr(widget, "_plain_text_copy_filters", [])
    text_edits = []
    if isinstance(widget, (QTextEdit, QTextBrowser)):
        text_edits.append(widget)
    text_edits.extend(widget.findChildren(QTextEdit))
    text_edits.extend(widget.findChildren(QTextBrowser))
    for text_edit in text_edits:
        if isinstance(text_edit, QTextEdit) and not text_edit.isReadOnly():
            text_edit.setAcceptRichText(False)
        if getattr(text_edit, "_plain_text_copy_filter_installed", False):
            continue
        copy_filter = PlainTextCopyFilter(text_edit)
        text_edit.installEventFilter(copy_filter)
        text_edit._plain_text_copy_filter_installed = True
        filters.append(copy_filter)
    widget._plain_text_copy_filters = filters
