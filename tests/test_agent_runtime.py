import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.config import AgentConfig
from agent.runtime import AgentRuntime, INVALID_TOOL_REQUEST_MESSAGE
from agent.tools import AgentTools


def make_runtime(tmp_path: Path, responses, config_data=None):
    config_path = tmp_path / "agent_config.json"
    config_path.write_text(json.dumps(config_data or {}), encoding="utf-8")
    config = AgentConfig(config_path=config_path, project_root=tmp_path)
    tools = AgentTools(config=config)
    queue = list(responses)

    def model_callback(messages):
        if queue:
            item = queue.pop(0)
            return item(messages) if callable(item) else item
        return "最终报告"

    return AgentRuntime(model_callback, config=config, tools=tools)


def parse_tool_result_message(message):
    assert message["role"] == "user"
    assert message["content"].startswith("工具执行结果:\n")
    return json.loads(message["content"].split("\n", 1)[1])


def test_runtime_completes_plain_response(tmp_path):
    runtime = make_runtime(tmp_path, ["这是分析结果"])

    result = runtime.run("分析项目")

    assert result.status == "completed"
    assert result.output == "这是分析结果"


def test_runtime_submit_preserves_conversation_history(tmp_path):
    runtime = make_runtime(tmp_path, [
        "第一轮",
        lambda messages: "历史用户数: " + str(sum(1 for msg in messages if msg["role"] == "user")),
    ])

    first = runtime.submit("任务一")
    second = runtime.submit("任务二")

    assert first.status == "completed"
    assert second.status == "completed"
    assert second.output == "历史用户数: 2"
    assert [msg["content"] for msg in second.messages if msg["role"] == "user"] == ["任务一", "任务二"]


def test_runtime_submit_resets_per_turn_budget(tmp_path):
    runtime = make_runtime(tmp_path, ["第一轮", "第二轮"], {"max_tool_calls": 1, "max_agent_steps": 1})

    first = runtime.submit("任务一")
    second = runtime.submit("任务二")

    assert first.status == "completed"
    assert second.status == "completed"
    assert second.output == "第二轮"


def test_runtime_waits_for_permission_then_executes_tool(tmp_path):
    runtime = make_runtime(tmp_path, [
        'TOOL_REQUEST: {"tool": "run_command", "args": {"command": "python --version"}}',
        lambda messages: "最终: " + parse_tool_result_message(messages[-1])["content"],
    ], {"permission_mode": "command", "allowed_commands": ["*"]})

    first = runtime.run("执行命令")
    assert first.status == "waiting_permission"
    assert first.pending_request.action == "run_command"

    final = runtime.continue_run("allow_once")
    assert final.status == "completed"
    assert "Python" in final.output
    assert final.tool_calls_used == 1


def test_runtime_executes_builtin_mcp_read_file_without_permission(tmp_path):
    (tmp_path / "README.md").write_text("project notes", encoding="utf-8")
    runtime = make_runtime(tmp_path, [
        'TOOL_REQUEST: {"tool": "read_file", "args": {"path": "README.md"}}',
        lambda messages: "最终: " + parse_tool_result_message(messages[-1])["content"],
    ])

    result = runtime.run("读取 README")

    assert result.status == "completed"
    assert "project notes" in result.output
    assert result.tool_calls_used == 1


def test_runtime_waits_for_permission_for_write_file(tmp_path):
    runtime = make_runtime(tmp_path, [
        'TOOL_REQUEST: {"tool": "write_file", "args": {"path": "notes.txt", "content": "ok"}}',
        lambda messages: "写入: " + parse_tool_result_message(messages[-1])["content"],
    ], {"permission_mode": "command"})

    first = runtime.run("写文件")

    assert first.status == "waiting_permission"
    assert first.pending_request.action == "write_file"

    final = runtime.continue_run("allow_once")

    assert final.status == "completed"
    assert (tmp_path / "notes.txt").read_text(encoding="utf-8") == "ok"


def test_runtime_waits_for_permission_for_external_mcp(tmp_path):
    server = tmp_path / "echo_mcp.py"
    server.write_text(
        "import json, sys\n"
        "request = json.loads(sys.stdin.readline())\n"
        "args = request['params']['arguments']\n"
        "print(json.dumps({'jsonrpc': '2.0', 'id': request['id'], 'result': {'content': [{'type': 'text', 'text': args['text']} ]}}))\n",
        encoding="utf-8",
    )
    config_data = {
        "permission_mode": "command",
        "mcp_servers": {
            "echo": {
                "command": sys.executable,
                "args": [str(server)],
                "tools": [{"name": "say", "required_args": ["text"], "allowed_args": ["text"]}],
            }
        },
        "enabled_mcp_tools": ["echo.say"],
    }
    runtime = make_runtime(tmp_path, [
        'TOOL_REQUEST: {"tool": "echo.say", "args": {"text": "external ok"}}',
        lambda messages: "外部: " + parse_tool_result_message(messages[-1])["content"],
    ], config_data)

    first = runtime.run("调用外部 MCP")
    assert first.status == "waiting_permission"
    assert first.pending_request.action == "echo.say"

    final = runtime.continue_run("allow_once")

    assert final.status == "completed"
    assert "external ok" in final.output


def test_runtime_direct_command_task_stops_after_tool_result(tmp_path):
    runtime = make_runtime(tmp_path, [
        'TOOL_REQUEST: {"tool": "run_command", "args": {"command": "python --version"}}',
        'TOOL_REQUEST: {"tool": "run_command", "args": {"command": "python --version"}}',
    ], {"permission_mode": "command", "allowed_commands": ["*"]})

    first = runtime.submit("执行命令 python --version")
    assert first.status == "waiting_permission"

    final = runtime.continue_run("allow_once")

    assert final.status == "completed"
    assert "Python" in final.output
    assert final.tool_calls_used == 1
    assert final.pending_request is None
    assert sum(1 for message in final.messages if message["role"] == "assistant") == 0


def test_runtime_direct_command_task_does_not_call_model(tmp_path):
    config = AgentConfig(config_path=tmp_path / "agent_config.json", project_root=tmp_path)
    config.update({"permission_mode": "command", "allowed_commands": ["*"], "require_confirmation_for_command": True})
    tools = AgentTools(config=config)

    def model_callback(messages):
        raise AssertionError("model should not be called for direct command tasks")

    runtime = AgentRuntime(model_callback, config=config, tools=tools)

    first = runtime.submit("运行 python --version")

    assert first.status == "waiting_permission"
    assert first.pending_request.action == "run_command"
    assert first.pending_request.target == "python --version"


def test_runtime_direct_tool_task_stops_after_denial(tmp_path):
    runtime = make_runtime(tmp_path, [
        'TOOL_REQUEST: {"tool": "run_command", "args": {"command": "echo hello"}}',
    ], {"permission_mode": "command", "allowed_commands": ["*"]})

    first = runtime.submit("执行命令 echo hello")
    assert first.status == "waiting_permission"

    final = runtime.continue_run("deny")

    assert final.status == "completed"
    assert final.tool_calls_used == 0
    assert final.pending_request is None
    assert parse_tool_result_message(final.messages[-1])["error"] == "user_denied"


def test_runtime_user_denial_returns_tool_error_to_model(tmp_path):
    runtime = make_runtime(tmp_path, [
        'TOOL_REQUEST: {"tool": "run_command", "args": {"command": "echo hello"}}',
        lambda messages: "收到: " + parse_tool_result_message(messages[-1])["error"],
    ], {"permission_mode": "command", "allowed_commands": ["*"]})

    first = runtime.run("执行命令")
    assert first.status == "waiting_permission"

    final = runtime.continue_run("deny")
    assert final.status == "completed"
    assert "user_denied" in final.output
    assert final.tool_calls_used == 0


def test_runtime_rejects_invalid_tool_without_execution(tmp_path):
    runtime = make_runtime(tmp_path, [
        'TOOL_REQUEST: {"tool": "delete_file", "args": {"path": "main.py"}}',
        lambda messages: "错误: " + parse_tool_result_message(messages[-1])["error"],
    ])

    result = runtime.run("写文件")

    assert result.status == "completed"
    assert "invalid_tool" in result.output
    assert result.tool_calls_used == 0


def test_runtime_rejects_invalid_tool_args_without_exception(tmp_path):
    runtime = make_runtime(tmp_path, [
        'TOOL_REQUEST: {"tool": "run_command", "args": {"command": ["echo"]}}',
        lambda messages: "错误: " + parse_tool_result_message(messages[-1])["error"],
    ])

    result = runtime.run("错误参数")

    assert result.status == "completed"
    assert "invalid_command_arg" in result.output
    assert result.tool_calls_used == 0


def test_runtime_rejects_extra_tool_args(tmp_path):
    runtime = make_runtime(tmp_path, [
        'TOOL_REQUEST: {"tool": "run_command", "args": {"command": "echo hi", "unexpected": true}}',
        lambda messages: "错误: " + parse_tool_result_message(messages[-1])["error"],
    ])

    result = runtime.run("额外参数")

    assert result.status == "completed"
    assert "invalid_tool_args" in result.output


def test_runtime_invalid_json_asks_model_to_retry(tmp_path):
    runtime = make_runtime(tmp_path, [
        'TOOL_REQUEST: {bad json',
        lambda messages: "重试提示: " + messages[-1]["content"],
    ])

    result = runtime.run("测试非法格式")

    assert result.status == "completed"
    assert INVALID_TOOL_REQUEST_MESSAGE in result.output


def test_system_prompt_documents_tool_contract(tmp_path):
    runtime = make_runtime(tmp_path, ["最终报告"])

    prompt = runtime._system_prompt()

    assert "TOOL_REQUEST:" in prompt
    assert "run_command" in prompt
    assert "不要附加解释" in prompt


def test_parse_tool_request_rejects_markdown_wrapped_json(tmp_path):
    runtime = make_runtime(tmp_path, ["最终报告"])

    parsed = runtime._parse_tool_request('```json\nTOOL_REQUEST: {"tool": "run_command", "args": {}}\n```')

    assert parsed is None


def test_runtime_budget_exhaustion(tmp_path):
    runtime = make_runtime(tmp_path, [
        'TOOL_REQUEST: {"tool": "run_command", "args": {"command": "python -c print(1)"}}',
        'TOOL_REQUEST: {"tool": "run_command", "args": {"command": "python -c print(2)"}}',
    ], {"permission_mode": "command", "allowed_commands": ["*"], "max_tool_calls": 1})

    first = runtime.run("检查项目，然后执行命令")
    assert first.status == "waiting_permission"
    result = runtime.continue_run("allow_once")

    assert result.status == "budget_exhausted"
    assert result.tool_calls_used == 1


def test_runtime_stop_from_pending_permission(tmp_path):
    runtime = make_runtime(tmp_path, [
        'TOOL_REQUEST: {"tool": "run_command", "args": {"command": "echo hi"}}',
    ], {"permission_mode": "command", "allowed_commands": ["*"]})

    first = runtime.run("执行")
    assert first.status == "waiting_permission"

    stopped = runtime.continue_run("stop")
    assert stopped.status == "stopped"
