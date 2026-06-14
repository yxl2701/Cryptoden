"""AI workspace panel with chat and restricted Agent modes."""

from PyQt5.QtWidgets import QTabWidget, QVBoxLayout, QWidget

from .agent_panel import AgentPanel
from .ai_panel import AIAssistantPanel


class AIWorkspacePanel(QWidget):
    """Container that switches between normal chat and Agent mode."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.mode_tabs = QTabWidget()
        self.mode_tabs.setDocumentMode(True)
        self.chat_panel = AIAssistantPanel(self)
        self.agent_panel = AgentPanel(self)
        self.mode_tabs.addTab(self.chat_panel, "对话模式")
        self.mode_tabs.addTab(self.agent_panel, "Agent模式")
        layout.addWidget(self.mode_tabs)

    def reload_config(self):
        self.chat_panel.reload_config()
