import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.config import AgentConfig
from agent.policy import AgentPolicy


def make_config(tmp_path: Path, data=None):
    config_path = tmp_path / "agent_config.json"
    config_path.write_text(json.dumps(data or {}), encoding="utf-8")
    return AgentConfig(config_path=config_path, project_root=tmp_path)


def test_unknown_action_is_denied(tmp_path):
    policy = AgentPolicy(make_config(tmp_path))

    decision = policy.check("delete_file", "main.py")

    assert decision.decision == "deny"
    assert decision.reason == "unknown_action"


def test_mcp_file_tools_stay_inside_workspace_and_protected_paths(tmp_path):
    policy = AgentPolicy(make_config(tmp_path))

    allowed = policy.check("read_file", "README.md")
    outside = policy.check("read_file", "../secret.txt")
    protected = policy.check("read_file", "agent/agent_config.json")

    assert allowed.decision == "allow"
    assert outside.reason == "path_outside_workspace"
    assert protected.reason == "protected_path"


def test_mcp_write_and_network_require_confirmation(tmp_path):
    policy = AgentPolicy(make_config(tmp_path, {"permission_mode": "command"}))

    write = policy.check("write_file", "notes.txt")
    network = policy.check("web_search", "cryptoden")

    assert write.decision == "ask"
    assert write.reason == "write_requires_confirmation"
    assert network.decision == "ask"
    assert network.reason == "network_requires_confirmation"


def test_command_mode_allows_only_whitelisted_non_destructive_commands(tmp_path):
    policy = AgentPolicy(make_config(tmp_path, {"permission_mode": "command"}))

    allowed = policy.check("run_command", "pytest")
    unknown = policy.check("run_command", "python setup.py clean")
    destructive = policy.check("run_command", "rm file.txt")

    assert allowed.decision == "ask"
    assert allowed.reason == "command_requires_confirmation"
    assert unknown.reason == "destructive_command_disabled"
    assert destructive.reason == "destructive_command_disabled"
