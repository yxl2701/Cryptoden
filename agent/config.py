"""Agent configuration loading with safe defaults."""

import json
from pathlib import Path
from typing import Any, Dict


AGENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = AGENT_DIR.parent
AGENT_CONFIG_FILE = AGENT_DIR / "agent_config.json"


DEFAULT_CONFIG: Dict[str, Any] = {
    "permission_mode": "command",
    "workspace_root": ".",
    "max_tool_calls": 20,
    "max_tool_calls_workspace_full": 40,
    "max_single_tool_result_chars": 20000,
    "max_total_tool_result_chars": 120000,
    "max_search_results": 100,
    "max_list_entries": 500,
    "max_agent_steps": 30,
    "max_read_file_bytes": 1048576,
    "require_confirmation_for_command": True,
    "require_confirmation_for_mcp": True,
    "enabled_command_tools": ["run_command"],
    "enabled_mcp_tools": ["run_command", "list_files", "read_file", "write_file", "search_text", "web_search"],
    "mcp_servers": {},
    "allowed_commands": ["*"],
    "ignored_paths": ["__pycache__", ".pytest_cache", "build", "dist", "*.egg-info", "logs", ".git"],
    "protected_paths": ["agent/agent_config.json", "config/ai_config.json", ".env"],
}

HARD_LIMITS = {
    "max_tool_calls": 50,
    "max_tool_calls_workspace_full": 50,
    "max_single_tool_result_chars": 50000,
    "max_total_tool_result_chars": 200000,
    "max_search_results": 300,
    "max_list_entries": 2000,
    "max_agent_steps": 80,
    "max_read_file_bytes": 5242880,
}


class AgentConfig:
    """Load and normalize agent config without exposing secrets to the model."""

    VALID_MODES = {"readonly", "writable", "command"}
    VALID_COMMAND_TOOLS = {"run_command"}
    VALID_MCP_TOOLS = {"run_command", "list_files", "read_file", "write_file", "search_text", "web_search"}

    def __init__(self, config_path: Path = None, project_root: Path = None):
        self.config_path = Path(config_path).resolve() if config_path else AGENT_CONFIG_FILE
        self.project_root = Path(project_root).resolve() if project_root else PROJECT_ROOT
        self.config = self._load()

    def _load(self) -> Dict[str, Any]:
        data = dict(DEFAULT_CONFIG)
        saved = self._read_saved_config()
        if isinstance(saved, dict):
            data.update(saved)

        data["permission_mode"] = self._normalize_permission_mode(data.get("permission_mode"))
        data["workspace_root"] = self._normalize_workspace_root(data.get("workspace_root"))

        for key, limit in HARD_LIMITS.items():
            data[key] = self._normalize_positive_int(data.get(key), DEFAULT_CONFIG[key], limit)

        for key in ("allowed_commands", "ignored_paths", "protected_paths", "enabled_command_tools", "enabled_mcp_tools"):
            if not isinstance(data.get(key), list):
                data[key] = list(DEFAULT_CONFIG[key])

        data["enabled_command_tools"] = self._normalize_enabled_command_tools(data.get("enabled_command_tools"))
        if not isinstance(data.get("mcp_servers"), dict):
            data["mcp_servers"] = {}
        data["enabled_mcp_tools"] = self._normalize_enabled_mcp_tools(data.get("enabled_mcp_tools"), data.get("mcp_servers"))
        data["protected_paths"] = self._merge_protected_paths(data.get("protected_paths", []))
        return data

    def _read_saved_config(self):
        try:
            if self.config_path.exists():
                return json.loads(self.config_path.read_text(encoding="utf-8"))
        except Exception:
            return None
        return None

    def _normalize_permission_mode(self, value: Any) -> str:
        if value in {"full", "workspace_full"}:
            return "command"
        if value == "approval":
            return "writable"
        if value in self.VALID_MODES:
            return value
        return "command"

    def _normalize_workspace_root(self, value: Any) -> str:
        if not isinstance(value, str) or not value.strip():
            return str(self.project_root)
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = self.project_root / candidate
        try:
            candidate = candidate.resolve()
            candidate.relative_to(self.project_root)
            return str(candidate)
        except Exception:
            return str(self.project_root)

    @staticmethod
    def _normalize_positive_int(value: Any, default: int, hard_limit: int) -> int:
        if not isinstance(value, int) or value <= 0:
            return default
        return min(value, hard_limit)

    @staticmethod
    def _merge_protected_paths(paths) -> list:
        hardcoded = [
            "agent/agent_config.json",
            "agent/config.py",
            "agent/policy.py",
            "agent/tools.py",
            "agent/mcp.py",
            "agent/runtime.py",
            "agent/permission_request.py",
            "config/ai_config.json",
            ".env",
        ]
        merged = []
        for path in list(paths) + hardcoded:
            if isinstance(path, str) and path not in merged:
                merged.append(path)
        return merged

    def get(self, key: str, default=None):
        return self.config.get(key, default)

    def update(self, values: Dict[str, Any]):
        data = dict(self.config)
        data.update(values)
        data["permission_mode"] = self._normalize_permission_mode(data.get("permission_mode"))
        data["enabled_command_tools"] = self._normalize_enabled_command_tools(data.get("enabled_command_tools"))
        if not isinstance(data.get("mcp_servers"), dict):
            data["mcp_servers"] = {}
        data["enabled_mcp_tools"] = self._normalize_enabled_mcp_tools(data.get("enabled_mcp_tools"), data.get("mcp_servers"))
        data["protected_paths"] = self._merge_protected_paths(data.get("protected_paths", []))
        self.config = data
        self.save()

    def save(self):
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(json.dumps(self._saved_config(), indent=2, ensure_ascii=False), encoding="utf-8")

    def _saved_config(self) -> Dict[str, Any]:
        data = dict(self.config)
        data["workspace_root"] = self._relative_workspace_root()
        return data

    def _relative_workspace_root(self) -> str:
        try:
            relative = self.workspace_root.relative_to(self.project_root)
        except Exception:
            return str(self.workspace_root)
        if str(relative) == ".":
            return "."
        return relative.as_posix()

    @property
    def permission_mode(self) -> str:
        return self.config["permission_mode"]

    @property
    def workspace_root(self) -> Path:
        return Path(self.config["workspace_root"]).resolve()

    def permission_summary(self) -> Dict[str, Any]:
        return {
            "permission_mode": self.permission_mode,
            "workspace_root": str(self.workspace_root),
            "max_tool_calls": self.get("max_tool_calls"),
            "require_confirmation_for_command": self.get("require_confirmation_for_command"),
            "require_confirmation_for_mcp": self.get("require_confirmation_for_mcp"),
            "enabled_command_tools": self.get("enabled_command_tools"),
            "enabled_mcp_tools": self.get("enabled_mcp_tools"),
        }

    @staticmethod
    def _normalize_enabled_command_tools(tools) -> list:
        if not isinstance(tools, list):
            return list(DEFAULT_CONFIG["enabled_command_tools"])
        enabled = []
        for tool in tools:
            if tool in AgentConfig.VALID_COMMAND_TOOLS and tool not in enabled:
                enabled.append(tool)
        return enabled

    @staticmethod
    def _normalize_enabled_mcp_tools(tools, servers=None) -> list:
        if not isinstance(tools, list):
            return list(DEFAULT_CONFIG["enabled_mcp_tools"])
        external_names = set()
        if isinstance(servers, dict):
            for server_name, server in servers.items():
                if not isinstance(server, dict):
                    continue
                server_tools = server.get("tools", [])
                if not isinstance(server_tools, list):
                    continue
                for tool in server_tools:
                    if isinstance(tool, dict) and isinstance(tool.get("name"), str):
                        external_names.add(f"{server_name}.{tool['name']}")
        enabled = []
        for tool in tools:
            if (tool in AgentConfig.VALID_MCP_TOOLS or tool in external_names) and tool not in enabled:
                enabled.append(tool)
        return enabled
