"""Local permission policy for the restricted agent."""

from dataclasses import dataclass
from pathlib import Path

from .config import AgentConfig


@dataclass(frozen=True)
class PermissionDecision:
    decision: str
    reason: str = ""

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"

    @property
    def denied(self) -> bool:
        return self.decision == "deny"

    @property
    def requires_approval(self) -> bool:
        return self.decision == "ask"


class AgentPolicy:
    """Enforce local MCP and command restrictions."""

    COMMAND_ACTIONS = {"run_command"}
    READ_ACTIONS = {"list_files", "read_file", "search_text"}
    WRITE_ACTIONS = {"write_file"}
    NETWORK_ACTIONS = {"web_search"}
    DESTRUCTIVE_COMMAND_PARTS = ("rm", "del", "remove", "erase", "rmdir", "rd", "format", "shutdown", "kill", "taskkill", "reset", "clean")

    def __init__(self, config: AgentConfig = None):
        self.config = config or AgentConfig()
        self.workspace_root = self.config.workspace_root

    def check(self, action: str, target: str = ".") -> PermissionDecision:
        if action in self.COMMAND_ACTIONS:
            return self._check_command(target)
        if action in self.READ_ACTIONS:
            return self._check_read(action, target)
        if action in self.WRITE_ACTIONS:
            return self._check_write(action, target)
        if action in self.NETWORK_ACTIONS:
            return self._check_network(action)
        if self._is_external_mcp(action):
            return self._check_external_mcp(action)
        if "." in action:
            return PermissionDecision("deny", "mcp_tool_disabled_by_user")
        return PermissionDecision("deny", "unknown_action")

    def check_workspace_path(self, target: str) -> PermissionDecision:
        return self._check_workspace_path(target)

    def _check_read(self, action: str, target: str) -> PermissionDecision:
        enabled = self._check_mcp_enabled(action)
        if enabled.denied:
            return enabled
        path_decision = self._check_workspace_path(target)
        if path_decision.denied:
            return path_decision
        return PermissionDecision("allow", "read_allowed")

    def _check_write(self, action: str, target: str) -> PermissionDecision:
        enabled = self._check_mcp_enabled(action)
        if enabled.denied:
            return enabled
        if self.config.permission_mode not in {"writable", "command"}:
            return PermissionDecision("deny", "write_mode_required")
        path_decision = self._check_workspace_path(target)
        if path_decision.denied:
            return path_decision
        if self.config.get("require_confirmation_for_mcp"):
            return PermissionDecision("ask", "write_requires_confirmation")
        return PermissionDecision("allow", "write_allowed_without_confirmation")

    def _check_network(self, action: str) -> PermissionDecision:
        enabled = self._check_mcp_enabled(action)
        if enabled.denied:
            return enabled
        if self.config.get("require_confirmation_for_mcp"):
            return PermissionDecision("ask", "network_requires_confirmation")
        return PermissionDecision("allow", "network_allowed_without_confirmation")

    def _check_external_mcp(self, action: str) -> PermissionDecision:
        enabled = self._check_mcp_enabled(action)
        if enabled.denied:
            return enabled
        if self.config.get("require_confirmation_for_mcp"):
            return PermissionDecision("ask", "external_mcp_requires_confirmation")
        return PermissionDecision("allow", "external_mcp_allowed_without_confirmation")

    def _check_mcp_enabled(self, action: str) -> PermissionDecision:
        if action not in self.config.get("enabled_mcp_tools", []):
            return PermissionDecision("deny", "mcp_tool_disabled_by_user")
        return PermissionDecision("allow", "mcp_tool_enabled")

    def _is_external_mcp(self, action: str) -> bool:
        if "." not in action:
            return False
        server_name, tool_name = action.split(".", 1)
        server = self.config.get("mcp_servers", {}).get(server_name)
        if not isinstance(server, dict):
            return False
        tools = server.get("tools", [])
        if not isinstance(tools, list):
            return False
        return any(isinstance(tool, dict) and tool.get("name") == tool_name for tool in tools)

    def _check_workspace_path(self, target: str) -> PermissionDecision:
        if not isinstance(target, str) or not target.strip():
            target = "."
        candidate = Path(target)
        if not candidate.is_absolute():
            candidate = self.workspace_root / candidate
        try:
            candidate = candidate.resolve()
            relative = candidate.relative_to(self.workspace_root)
        except Exception:
            return PermissionDecision("deny", "path_outside_workspace")
        relative_text = str(relative).replace("\\", "/")
        if self._is_protected_path(relative_text):
            return PermissionDecision("deny", "protected_path")
        return PermissionDecision("allow", "path_allowed")

    def _is_protected_path(self, relative_path: str) -> bool:
        for protected in self.config.get("protected_paths", []):
            protected = str(protected).replace("\\", "/").strip("/")
            if relative_path == protected or relative_path.startswith(protected + "/"):
                return True
        lowered = relative_path.lower()
        return any(part in lowered for part in (".env", "secret", "credential", "api_key"))

    def _check_command(self, command: str) -> PermissionDecision:
        enabled = self._check_mcp_enabled("run_command")
        if enabled.denied:
            return enabled
        if self.config.permission_mode != "command":
            return PermissionDecision("deny", "command_mode_required")
        if "run_command" not in self.config.get("enabled_command_tools", []):
            return PermissionDecision("deny", "tool_disabled_by_user")
        if not isinstance(command, str):
            return PermissionDecision("deny", "invalid_command")
        if self._is_destructive_command(command):
            return PermissionDecision("deny", "destructive_command_disabled")
        if not self._is_allowed_command(command):
            return PermissionDecision("deny", "command_not_allowed")
        if self.config.get("require_confirmation_for_command"):
            return PermissionDecision("ask", "command_requires_confirmation")
        return PermissionDecision("allow", "command_allowed_without_confirmation")

    def _is_destructive_command(self, command: str) -> bool:
        lowered = command.lower()
        tokens = lowered.replace("/", " ").replace("\\", " ").replace("-", " ").split()
        return any(part in tokens for part in self.DESTRUCTIVE_COMMAND_PARTS)

    def _is_allowed_command(self, command: str) -> bool:
        command = command.strip()
        if not command:
            return False

        for pattern in self.config.get("allowed_commands", []):
            if not isinstance(pattern, str):
                continue
            pattern = pattern.strip()
            if pattern == "*":
                return True
            if pattern.endswith("*") and command.startswith(pattern[:-1].strip()):
                return True
            if command == pattern:
                return True
        return False
