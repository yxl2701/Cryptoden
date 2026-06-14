import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.config import AgentConfig
from agent.tools import AgentTools


def make_tools(tmp_path: Path, data=None):
    config_path = tmp_path / "agent_config.json"
    config_path.write_text(json.dumps(data or {}), encoding="utf-8")
    config = AgentConfig(config_path=config_path, project_root=tmp_path)
    return AgentTools(config=config)


def test_run_command_requires_command_mode_and_allowlist(tmp_path):
    tools = make_tools(tmp_path, {"permission_mode": "command"})

    assert tools.run_command("rm notes.txt")["error"] == "destructive_command_disabled"
    assert tools.policy.check("run_command", "python unknown.py").reason == "command_requires_confirmation"


def test_run_command_respects_specific_allowlist(tmp_path):
    tools = make_tools(tmp_path, {"permission_mode": "command", "allowed_commands": ["pytest"]})

    assert tools.run_command("python unknown.py")["error"] == "command_not_allowed"
    assert tools.policy.check("run_command", "pytest").reason == "command_requires_confirmation"


def test_builtin_mcp_file_tools_read_write_and_search(tmp_path):
    (tmp_path / "notes.txt").write_text("hello cryptoden", encoding="utf-8")
    tools = make_tools(tmp_path, {"permission_mode": "command", "require_confirmation_for_mcp": False})

    listed = tools.execute("list_files", {"path": "."})
    read = tools.execute("read_file", {"path": "notes.txt"})
    search = tools.execute("search_text", {"query": "cryptoden", "path": ".", "glob": "*.txt"})
    written = tools.execute("write_file", {"path": "out/result.txt", "content": "done"})

    assert listed["success"] is True
    assert "notes.txt" in listed["content"]
    assert read["content"] == "hello cryptoden"
    assert "notes.txt:1" in search["content"]
    assert written["success"] is True
    assert (tmp_path / "out" / "result.txt").read_text(encoding="utf-8") == "done"


def test_builtin_mcp_file_tools_reject_protected_paths(tmp_path):
    tools = make_tools(tmp_path)

    result = tools.execute("read_file", {"path": "agent/agent_config.json"})

    assert result["success"] is False
    assert result["error"] == "protected_path"


def test_search_text_does_not_require_read_file_tool_enabled(tmp_path):
    (tmp_path / "notes.txt").write_text("hello cryptoden", encoding="utf-8")
    tools = make_tools(tmp_path, {
        "enabled_mcp_tools": ["search_text"],
    })

    result = tools.execute("search_text", {"query": "cryptoden", "path": ".", "glob": "*.txt"})

    assert result["success"] is True
    assert "notes.txt:1" in result["content"]


def test_external_stdio_mcp_tool_parses_jsonrpc_content(tmp_path):
    server = tmp_path / "echo_mcp.py"
    server.write_text(
        "import json, sys\n"
        "request = json.loads(sys.stdin.readline())\n"
        "args = request['params']['arguments']\n"
        "print(json.dumps({\n"
        "    'jsonrpc': '2.0',\n"
        "    'id': request['id'],\n"
        "    'result': {'content': [{'type': 'text', 'text': 'echo:' + args['text']}]}\n"
        "}))\n",
        encoding="utf-8",
    )
    tools = make_tools(tmp_path, {
        "permission_mode": "command",
        "require_confirmation_for_mcp": False,
        "mcp_servers": {
            "echo": {
                "command": sys.executable,
                "args": [str(server)],
                "tools": [{"name": "say", "required_args": ["text"], "allowed_args": ["text"]}],
            }
        },
        "enabled_mcp_tools": ["echo.say"],
    })

    result = tools.execute("echo.say", {"text": "hello"})

    assert result["success"] is True
    assert result["content"] == "echo:hello"


def test_external_stdio_mcp_tool_returns_jsonrpc_error(tmp_path):
    server = tmp_path / "error_mcp.py"
    server.write_text(
        "import json, sys\n"
        "request = json.loads(sys.stdin.readline())\n"
        "print(json.dumps({'jsonrpc': '2.0', 'id': request['id'], 'error': {'code': -32000, 'message': 'boom'}}))\n",
        encoding="utf-8",
    )
    tools = make_tools(tmp_path, {
        "permission_mode": "command",
        "require_confirmation_for_mcp": False,
        "mcp_servers": {
            "bad": {
                "command": sys.executable,
                "args": [str(server)],
                "tools": [{"name": "fail", "required_args": [], "allowed_args": []}],
            }
        },
        "enabled_mcp_tools": ["bad.fail"],
    })

    result = tools.execute("bad.fail", {})

    assert result["success"] is False
    assert result["error"] == "boom"


def test_external_stdio_mcp_tool_treats_is_error_content_as_error(tmp_path):
    server = tmp_path / "is_error_mcp.py"
    server.write_text(
        "import json, sys\n"
        "request = json.loads(sys.stdin.readline())\n"
        "print(json.dumps({\n"
        "    'jsonrpc': '2.0',\n"
        "    'id': request['id'],\n"
        "    'result': {'isError': True, 'content': [{'type': 'text', 'text': 'tool failed'}]}\n"
        "}))\n",
        encoding="utf-8",
    )
    tools = make_tools(tmp_path, {
        "permission_mode": "command",
        "require_confirmation_for_mcp": False,
        "mcp_servers": {
            "bad": {
                "command": sys.executable,
                "args": [str(server)],
                "tools": [{"name": "fail", "required_args": [], "allowed_args": []}],
            }
        },
        "enabled_mcp_tools": ["bad.fail"],
    })

    result = tools.execute("bad.fail", {})

    assert result["success"] is False
    assert result["error"] == "tool failed"
