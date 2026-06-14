"""Restricted Agent analysis panel."""

import json

from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextBrowser,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from agent.config import AgentConfig
from agent.runtime import AgentRuntime, TOOL_REQUEST_PREFIX
from agent.tools import AgentTools
from utils.ai_assistant import AIClient, AIConfig
from .clipboard_utils import install_plain_text_copy
from .file_drop_helper import TextFileDropHelper

try:
    import markdown
    MARKDOWN_AVAILABLE = True
except ImportError:
    MARKDOWN_AVAILABLE = False


class AgentWorker(QThread):
    result_ready = pyqtSignal(object)
    error_occurred = pyqtSignal(str)
    chunk_ready = pyqtSignal(str)

    def __init__(self, runtime: AgentRuntime, task: str = None, permission_decision: str = None):
        super().__init__()
        self.runtime = runtime
        self.task = task
        self.permission_decision = permission_decision

    def run(self):
        try:
            self.runtime.chunk_callback = self.chunk_ready.emit
            if self.task is not None:
                result = self.runtime.submit(self.task)
            else:
                result = self.runtime.continue_run(self.permission_decision)
            self.result_ready.emit(result)
        except Exception as exc:
            self.error_occurred.emit(str(exc))


class AgentPanel(QWidget):
    """GUI for the restricted readonly Agent mode."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.agent_config = AgentConfig()
        self.tools = AgentTools(config=self.agent_config)
        self.ai_config = AIConfig()
        self.input_drop_helper = None
        self.runtime = None
        self.worker = None
        self.pending_request = None
        self.current_agent_content = ""
        self._base_output_html = ""
        self._streaming_active = False
        self._suppress_scroll_tracking = False
        self._tracked_scroll_value = 0
        self._tracked_at_bottom = True
        self._append_revision = 0
        self._displayed_tool_result_count = 0
        self.setup_ui()
        install_plain_text_copy(self)
        self.input_drop_helper = TextFileDropHelper(self, self.input_edit)
        self.refresh_summary()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(10, 10, 10, 10)

        header = QHBoxLayout()
        title = QLabel("Agent分析")
        title.setStyleSheet("font-size: 12pt; font-weight: bold; color: #333;")
        header.addWidget(title)
        header.addStretch()
        self.summary_label = QLabel("")
        self.summary_label.setStyleSheet("color: #666;")
        header.addWidget(self.summary_label)
        layout.addLayout(header)

        self.output = QTextBrowser()
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Microsoft YaHei", 10))
        self.output.setStyleSheet("""
            QTextBrowser {
                background-color: #FAFAFA;
                border: 1px solid #E0E0E0;
                border-radius: 6px;
                padding: 10px;
            }
        """)
        self.output.verticalScrollBar().valueChanged.connect(self._on_output_scroll_changed)
        layout.addWidget(self.output, stretch=1)

        self.permission_frame = QFrame()
        self.permission_frame.setStyleSheet("""
            QFrame {
                background-color: #FFF8E1;
                border: 1px solid #FFCC80;
                border-radius: 6px;
                padding: 8px;
            }
        """)
        permission_layout = QHBoxLayout(self.permission_frame)
        self.permission_label = QLabel("")
        self.permission_label.setWordWrap(True)
        permission_layout.addWidget(self.permission_label, stretch=1)
        self.allow_btn = QPushButton("允许一次")
        self.allow_btn.clicked.connect(lambda: self.continue_with_permission("allow_once"))
        permission_layout.addWidget(self.allow_btn)
        self.deny_btn = QPushButton("拒绝")
        self.deny_btn.clicked.connect(lambda: self.continue_with_permission("deny"))
        permission_layout.addWidget(self.deny_btn)
        self.permission_frame.hide()
        layout.addWidget(self.permission_frame)

        input_group = QGroupBox("任务")
        input_layout = QVBoxLayout(input_group)
        self.input_edit = QTextEdit()
        self.input_edit.setPlaceholderText("输入项目分析任务，例如：梳理 AI 相关模块职责")
        self.input_edit.setMaximumHeight(100)
        self.input_edit.setFont(QFont("Microsoft YaHei", 10))
        self.input_edit.installEventFilter(self)
        input_layout.addWidget(self.input_edit)

        button_row = QHBoxLayout()
        button_row.addStretch()
        self.run_btn = QPushButton("运行 Agent")
        self.run_btn.setFixedSize(120, 38)
        self.run_btn.clicked.connect(self.run_agent)
        button_row.addWidget(self.run_btn)
        self.stop_btn = QPushButton("停止")
        self.stop_btn.setFixedSize(90, 38)
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_agent)
        button_row.addWidget(self.stop_btn)
        self.clear_btn = QPushButton("清空")
        self.clear_btn.setFixedSize(90, 38)
        self.clear_btn.clicked.connect(self.clear_output)
        button_row.addWidget(self.clear_btn)
        input_layout.addLayout(button_row)
        layout.addWidget(input_group)

    def refresh_summary(self):
        summary = self.agent_config.permission_summary()
        self.summary_label.setText(
            f"权限: {summary['permission_mode']} | 命令确认: {summary['require_confirmation_for_command']} | MCP确认: {summary['require_confirmation_for_mcp']} | MCP工具: {len(summary['enabled_mcp_tools'])} | 工具预算: {summary['max_tool_calls']} | Workspace: {summary['workspace_root']}"
        )

    def reload_permission_config(self):
        self.agent_config = AgentConfig()
        self.tools = AgentTools(config=self.agent_config)
        self.runtime = None
        self.pending_request = None
        self.permission_frame.hide()
        self._displayed_tool_result_count = 0
        self.refresh_summary()

    def run_agent(self):
        task = self.input_edit.toPlainText().strip()
        if not task:
            self.append_output("请输入任务。")
            return

        self.input_edit.clear()
        if self.runtime is None:
            self.agent_config = AgentConfig()
            self.tools = AgentTools(config=self.agent_config)
            client = AIClient(AIConfig())
            self.runtime = AgentRuntime.with_ai_client(client, config=self.agent_config, tools=self.tools)
            self._displayed_tool_result_count = 0
        self.pending_request = None
        self.current_agent_content = ""
        self._streaming_active = False
        self.permission_frame.hide()
        self.append_block("用户任务", task)
        self.refresh_summary()
        self.start_worker(task=task)

    def continue_with_permission(self, decision: str):
        if not self.runtime or not self.pending_request:
            return
        self.permission_frame.hide()
        self.append_block("权限决策", self._decision_label(decision))
        self.current_agent_content = ""
        self._streaming_active = False
        self.start_worker(permission_decision=decision)

    def stop_agent(self):
        if self.worker and self.worker.isRunning():
            self.worker.terminate()
            self.worker.wait(1000)
        if self.runtime:
            result = self.runtime.stop()
            self.handle_result(result)
        self.set_running(False)

    def start_worker(self, task: str = None, permission_decision: str = None):
        self.set_running(True)
        self.worker = AgentWorker(self.runtime, task=task, permission_decision=permission_decision)
        self.worker.chunk_ready.connect(self.handle_chunk)
        self.worker.result_ready.connect(self.handle_result)
        self.worker.error_occurred.connect(self.handle_error)
        self.worker.finished.connect(lambda: self.set_running(False))
        self.worker.start()

    def handle_result(self, result):
        self.display_new_tool_results(result)
        if result.status == "waiting_permission":
            self.pending_request = result.pending_request
            self.append_status(result)
            self.show_permission_request(result.pending_request)
            return

        self.pending_request = None
        self.permission_frame.hide()
        if result.output and not self._output_is_last_tool_result(result.output, result):
            if self._streaming_active:
                self._streaming_active = False
                self._base_output_html = self.output.toHtml()
            else:
                self.finish_streaming_block(result.output)
        else:
            self._streaming_active = False
        self.append_status(result)

    def append_status(self, result):
        self.append_block("状态", f"{self._status_label(result.status)} | 本轮已用工具: {result.tool_calls_used}")

    def display_new_tool_results(self, result):
        tool_messages = [
            message["content"]
            for message in result.messages
            if message.get("role") == "user" and message.get("content", "").startswith("工具执行结果:\n")
        ]
        for content in tool_messages[self._displayed_tool_result_count:]:
            self.append_block("工具执行结果", self._format_tool_result(content))
        self._displayed_tool_result_count = len(tool_messages)

    def _output_is_last_tool_result(self, output: str, result) -> bool:
        for message in reversed(result.messages):
            content = message.get("content", "")
            if message.get("role") == "user" and content.startswith("工具执行结果:\n"):
                return output == self._format_tool_result(content)
        return False

    @staticmethod
    def _format_tool_result(content: str) -> str:
        try:
            payload = content.split("\n", 1)[1]
            result = json.loads(payload)
        except (json.JSONDecodeError, IndexError):
            return content

        if result.get("success"):
            text = result.get("content", "")
            if result.get("truncated"):
                text += "\n[结果已截断]"
            return text or "[空结果]"

        return "错误: " + str(result.get("error", "unknown_error"))

    def show_permission_request(self, request):
        if not request:
            return
        self.permission_label.setText(
            f"Agent 请求工具权限\n操作: {request.action}\n目标: {request.target}\n原因: {request.reason}\n风险: {request.risk_level}"
        )
        self.permission_frame.show()
        self.append_block("等待权限确认", f"操作: {request.action}\n目标: {request.target}\n原因: {request.reason}\n风险: {request.risk_level}")

    def handle_error(self, error: str):
        self.append_block("错误", error)
        self.set_running(False)

    def handle_chunk(self, chunk: str):
        pending_content = self.current_agent_content + chunk
        stripped = pending_content.strip()
        if TOOL_REQUEST_PREFIX.startswith(stripped) or stripped.startswith(TOOL_REQUEST_PREFIX):
            self.current_agent_content = pending_content
            return
        self.current_agent_content = pending_content
        self.render_streaming_block(self.current_agent_content)

    def set_running(self, running: bool):
        has_pending = self.pending_request is not None
        self.run_btn.setEnabled(not running and not has_pending)
        self.stop_btn.setEnabled(running or has_pending)
        self.allow_btn.setEnabled(has_pending and not running)
        self.deny_btn.setEnabled(has_pending and not running)

    def append_output(self, text: str):
        old_value, at_bottom, revision = self._before_append()
        self.output.append(self._escape_html(text).replace("\n", "<br>"))
        self._after_append(old_value, at_bottom, revision)

    def append_block(self, title: str, text: str):
        old_value, at_bottom, revision = self._before_append()
        html = self._plain_block_html(title, text)
        self.output.append(html)
        self._base_output_html = self.output.toHtml()
        self._after_append(old_value, at_bottom, revision)

    def render_streaming_block(self, text: str):
        self._streaming_active = True
        self._set_output_html(self._base_output_html + self._markdown_block_html("Agent", text))

    def finish_streaming_block(self, final_text: str):
        self.current_agent_content = final_text
        self._set_output_html(self._base_output_html + self._markdown_block_html("Agent", final_text))
        self._base_output_html = self.output.toHtml()
        self._streaming_active = False

    def _set_output_html(self, html: str):
        old_value, at_bottom, revision = self._before_append()
        self.output.setHtml(html)
        self._after_append(old_value, at_bottom, revision)

    def _plain_block_html(self, title: str, text: str) -> str:
        if title in ("用户任务", "你"):
            align = "right"
            bg = "#D6EAF8"
            border = ""
            name_color = "#1A5276"
            table_align = "margin-left:auto"
        elif title in ("Agent", "AI", "AI分析"):
            align = "left"
            bg = "#E8F5E9"
            border = "border:1px solid #81C784;"
            name_color = "#2E7D32"
            table_align = ""
        else:
            align = "left"
            bg = "#F8F9FA"
            border = ""
            name_color = "#555"
            table_align = ""
        return f"""
<div align="{align}" style="margin:4px 0;">
  <table style="{table_align};background:{bg};{border}border-radius:6px;padding:8px 12px;"><tr><td>
    <div style="color:{name_color};font-weight:bold;font-size:9pt;">{self._escape_html(title)}</div>
    <div style="white-space:pre-wrap;line-height:1.5;color:#1C2833;">{self._escape_html(text)}</div>
  </td></tr></table>
</div>
"""

    def _markdown_block_html(self, title: str, text: str) -> str:
        if title in ("用户任务", "你"):
            align = "right"
            bg = "#D6EAF8"
            border = ""
            name_color = "#1A5276"
            table_align = "margin-left:auto"
        elif title in ("Agent", "AI", "AI分析"):
            align = "left"
            bg = "#E8F5E9"
            border = "border:1px solid #81C784;"
            name_color = "#2E7D32"
            table_align = ""
        else:
            align = "left"
            bg = "#F8F9FA"
            border = ""
            name_color = "#555"
            table_align = ""
        return f"""
<div align="{align}" style="margin:4px 0;">
  <table style="{table_align};background:{bg};{border}border-radius:6px;padding:8px 12px;"><tr><td>
    <div style="color:{name_color};font-weight:bold;font-size:9pt;">{self._escape_html(title)}</div>
    <div style="line-height:1.6;color:#1C2833;">{self._render_markdown(text)}</div>
  </td></tr></table>
</div>
"""

    def _render_markdown(self, text: str) -> str:
        if MARKDOWN_AVAILABLE:
            try:
                return markdown.markdown(text, extensions=['fenced_code', 'codehilite', 'tables'])
            except Exception:
                pass
        return self._escape_html(text).replace("\n", "<br>")

    def _on_output_scroll_changed(self, value):
        if self._suppress_scroll_tracking:
            return
        scroll_bar = self.output.verticalScrollBar()
        self._tracked_scroll_value = value
        self._tracked_at_bottom = value >= scroll_bar.maximum() - 30

    def _before_append(self):
        self._append_revision += 1
        self._suppress_scroll_tracking = True
        return self._tracked_scroll_value, self._tracked_at_bottom, self._append_revision

    def _after_append(self, old_value, at_bottom, revision):
        QTimer.singleShot(0, lambda: self._restore_scroll_position(old_value, at_bottom, revision))

    def _restore_scroll_position(self, old_value, at_bottom, revision):
        if revision != self._append_revision:
            return
        scroll_bar = self.output.verticalScrollBar()
        if at_bottom:
            scroll_bar.setValue(scroll_bar.maximum())
        else:
            scroll_bar.setValue(min(old_value, scroll_bar.maximum()))
        self._tracked_scroll_value = scroll_bar.value()
        self._tracked_at_bottom = scroll_bar.value() >= scroll_bar.maximum() - 30
        self._suppress_scroll_tracking = False

    def clear_output(self):
        self.output.clear()
        self._base_output_html = ""
        self.current_agent_content = ""
        self._streaming_active = False
        self.runtime = None
        self.pending_request = None
        self.permission_frame.hide()
        self._tracked_scroll_value = 0
        self._tracked_at_bottom = True
        self._displayed_tool_result_count = 0
        self.set_running(False)

    @staticmethod
    def _escape_html(text: str) -> str:
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    @staticmethod
    def _decision_label(decision: str) -> str:
        labels = {
            "allow_once": "允许本次工具调用",
            "deny": "拒绝本次工具调用",
            "stop": "停止 Agent",
        }
        return labels.get(decision, decision)

    @staticmethod
    def _status_label(status: str) -> str:
        labels = {
            "completed": "已完成",
            "waiting_permission": "等待权限确认",
            "budget_exhausted": "工具预算已耗尽",
            "step_limit_reached": "循环轮数已耗尽",
            "stopped": "已停止",
        }
        return labels.get(status, status)

    def eventFilter(self, obj, event):
        if obj == self.input_edit:
            if self.input_drop_helper and self.input_drop_helper.eventFilter(obj, event):
                return True
            if event.type() == event.KeyPress:
                if event.key() == Qt.Key_Return and not event.modifiers() & Qt.ShiftModifier:
                    self.run_agent()
                    return True
        return super().eventFilter(obj, event)
