import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.config import AgentConfig


def write_config(path: Path, data):
    path.write_text(json.dumps(data), encoding="utf-8")


def test_missing_config_uses_safe_defaults(tmp_path):
    config = AgentConfig(config_path=tmp_path / "missing.json", project_root=tmp_path)

    assert config.permission_mode == "command"
    assert config.workspace_root == tmp_path.resolve()
    assert config.get("max_tool_calls") == 20
    assert config.get("enabled_command_tools") == ["run_command"]
    assert "read_file" in config.get("enabled_mcp_tools")


def test_invalid_json_uses_safe_defaults(tmp_path):
    config_path = tmp_path / "agent_config.json"
    config_path.write_text("{bad json", encoding="utf-8")

    config = AgentConfig(config_path=config_path, project_root=tmp_path)

    assert config.permission_mode == "command"
    assert config.workspace_root == tmp_path.resolve()


def test_budget_limits(tmp_path):
    config_path = tmp_path / "agent_config.json"
    write_config(config_path, {
        "max_tool_calls": 500,
        "max_agent_steps": -1,
    })

    config = AgentConfig(config_path=config_path, project_root=tmp_path)

    assert config.permission_mode == "command"
    assert config.get("max_tool_calls") == 50
    assert config.get("max_agent_steps") == 30


def test_workspace_root_cannot_escape_project(tmp_path):
    outside = tmp_path.parent
    config_path = tmp_path / "agent_config.json"
    write_config(config_path, {"workspace_root": str(outside)})

    config = AgentConfig(config_path=config_path, project_root=tmp_path)

    assert config.workspace_root == tmp_path.resolve()


def test_hardcoded_protected_paths_are_always_merged(tmp_path):
    config_path = tmp_path / "agent_config.json"
    write_config(config_path, {"protected_paths": []})

    config = AgentConfig(config_path=config_path, project_root=tmp_path)

    protected = config.get("protected_paths")

    assert "agent/agent_config.json" in protected
    assert "agent/policy.py" in protected
    assert "agent/mcp.py" in protected
    assert "config/ai_config.json" in protected


def test_enabled_command_tools_are_normalized(tmp_path):
    config_path = tmp_path / "agent_config.json"
    write_config(config_path, {"enabled_command_tools": ["run_command", "list_files", "run_command"]})

    config = AgentConfig(config_path=config_path, project_root=tmp_path)

    assert config.get("enabled_command_tools") == ["run_command"]


def test_enabled_mcp_tools_include_declared_external_tools(tmp_path):
    config_path = tmp_path / "agent_config.json"
    write_config(config_path, {
        "mcp_servers": {
            "notes": {
                "command": "python",
                "tools": [{"name": "lookup", "required_args": ["query"]}],
            }
        },
        "enabled_mcp_tools": ["read_file", "notes.lookup", "unknown.tool"],
    })

    config = AgentConfig(config_path=config_path, project_root=tmp_path)

    assert config.get("enabled_mcp_tools") == ["read_file", "notes.lookup"]


def test_update_saves_permission_settings(tmp_path):
    config_path = tmp_path / "agent_config.json"
    config = AgentConfig(config_path=config_path, project_root=tmp_path)

    config.update({
        "require_confirmation_for_command": False,
    })
    reloaded = AgentConfig(config_path=config_path, project_root=tmp_path)

    assert reloaded.get("require_confirmation_for_command") is False
    assert reloaded.get("enabled_command_tools") == ["run_command"]


def test_save_preserves_workspace_root_as_relative_path(tmp_path):
    config_path = tmp_path / "agent_config.json"
    config = AgentConfig(config_path=config_path, project_root=tmp_path)

    config.save()

    saved = json.loads(config_path.read_text(encoding="utf-8"))
    assert saved["workspace_root"] == "."
