"""Minimal restricted agent runtime skeleton."""

import json
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .config import AgentConfig
from .model import AgentModel
from .permission_request import PermissionRequest
from .tools import AgentTools


TOOL_REQUEST_PREFIX = "TOOL_REQUEST:"
INVALID_TOOL_REQUEST_MESSAGE = "工具请求格式无效。只输出 TOOL_REQUEST: 后接单个 JSON 对象，不要使用 Markdown 代码块。"


@dataclass
class AgentRunResult:
    status: str
    output: str = ""
    messages: List[Dict] = field(default_factory=list)
    pending_request: Optional[PermissionRequest] = None
    tool_calls_used: int = 0


class AgentRuntime:
    """Run a safe tool-calling loop independent of GUI and real model clients."""

    def __init__(self, model_callback: Callable[[List[Dict]], str], config: AgentConfig = None, tools: AgentTools = None, chunk_callback: Callable[[str], None] = None):
        self.config = config or AgentConfig()
        self.tools = tools or AgentTools(config=self.config)
        self.model_callback = model_callback
        self.chunk_callback = chunk_callback
        self.messages: List[Dict] = []
        self.tool_calls_used = 0
        self.steps_used = 0
        self.stopped = False
        self.pending_tool_request: Optional[Dict] = None
        self.pending_permission_request: Optional[PermissionRequest] = None
        self.current_task = ""
        self.direct_tool_task = False

    @classmethod
    def with_ai_client(cls, ai_client=None, config: AgentConfig = None, tools: AgentTools = None, chunk_callback: Callable[[str], None] = None):
        model = AgentModel(ai_client)
        return cls(model.stream, config=config, tools=tools, chunk_callback=chunk_callback)

    def run(self, task: str) -> AgentRunResult:
        self.messages = [
            {"role": "system", "content": self._system_prompt()},
            {"role": "user", "content": task},
        ]
        self.tool_calls_used = 0
        self.steps_used = 0
        self.stopped = False
        self.pending_tool_request = None
        self.pending_permission_request = None
        self.current_task = task
        self.direct_tool_task = self._is_direct_tool_task(task)
        direct_request = self._direct_tool_request_from_task(task)
        if direct_request:
            return self._prepare_tool_call(direct_request) or self._result("completed")
        return self.continue_run()

    def submit(self, task: str) -> AgentRunResult:
        """Append a user task to the current conversation and continue."""
        if not self.messages:
            self.messages.append({"role": "system", "content": self._system_prompt()})
        self.messages.append({"role": "user", "content": task})
        self.tool_calls_used = 0
        self.steps_used = 0
        self.stopped = False
        self.pending_tool_request = None
        self.pending_permission_request = None
        self.current_task = task
        self.direct_tool_task = self._is_direct_tool_task(task)
        direct_request = self._direct_tool_request_from_task(task)
        if direct_request:
            return self._prepare_tool_call(direct_request) or self._result("completed")
        return self.continue_run()

    def continue_run(self, permission_decision: str = None) -> AgentRunResult:
        if self.stopped:
            return self._result("stopped", "Agent 已停止")

        if self.pending_permission_request:
            return self._handle_pending_permission(permission_decision)

        while self.steps_used < self.config.get("max_agent_steps"):
            if self.tool_calls_used >= self.config.get("max_tool_calls"):
                return self._result("budget_exhausted", "工具调用预算已耗尽")

            self.steps_used += 1
            response = self._call_model()
            if not isinstance(response, str):
                response = str(response)
            self.messages.append({"role": "assistant", "content": response})

            tool_request = self._parse_tool_request(response)
            if tool_request is None:
                return self._result("completed", response)
            if tool_request == "invalid":
                self.messages.append({"role": "user", "content": INVALID_TOOL_REQUEST_MESSAGE})
                continue

            request_result = self._prepare_tool_call(tool_request)
            if request_result:
                return request_result

        return self._result("step_limit_reached", "Agent 循环轮数已耗尽")

    def stop(self) -> AgentRunResult:
        self.stopped = True
        if self.pending_permission_request:
            self.pending_permission_request.stop()
        return self._result("stopped", "Agent 已停止")

    def _handle_pending_permission(self, permission_decision: str = None) -> AgentRunResult:
        if permission_decision is None:
            return self._result("waiting_permission", pending_request=self.pending_permission_request)
        if permission_decision == "stop":
            return self.stop()

        request = self.pending_permission_request
        tool_request = self.pending_tool_request
        self.pending_permission_request = None
        self.pending_tool_request = None

        if permission_decision != "allow_once":
            result = {"success": False, "error": "user_denied"}
            self._append_tool_result(result)
            if self.direct_tool_task:
                return self._result("completed", self._tool_result_output(result))
            return self.continue_run()

        return self._execute_tool_and_continue(tool_request, request)

    def _prepare_tool_call(self, tool_request: Dict) -> Optional[AgentRunResult]:
        name = tool_request.get("tool")
        args = tool_request.get("args", {})
        if not self.tools.has_tool(name) or not isinstance(args, dict):
            self._append_tool_result({"success": False, "error": "invalid_tool"})
            return None

        validation_error = self._validate_tool_args(name, args)
        if validation_error:
            self._append_tool_result({"success": False, "error": validation_error})
            return None

        target = self.tools.target_for(name, args)
        decision = self.tools.policy.check(name, target)
        if decision.denied:
            result = {"success": False, "error": decision.reason}
            self._append_tool_result(result)
            if self.direct_tool_task:
                return self._result("completed", self._tool_result_output(result))
            return None
        if decision.requires_approval:
            self.pending_tool_request = tool_request
            self.pending_permission_request = PermissionRequest.from_decision(name, target, decision)
            return self._result("waiting_permission", pending_request=self.pending_permission_request)

        return self._execute_tool_and_continue(tool_request)

    def _execute_tool_and_continue(self, tool_request: Dict, request: PermissionRequest = None) -> AgentRunResult:
        name = tool_request["tool"]
        args = tool_request.get("args", {})
        result = self.tools.execute(name, args)
        self.tool_calls_used += 1
        if request:
            request.allow_once()
        self._append_tool_result(result)
        if self.direct_tool_task:
            return self._result("completed", self._tool_result_output(result))
        return self.continue_run()

    def _append_tool_result(self, result: Dict):
        content = "工具执行结果:\n" + json.dumps(result, ensure_ascii=False)
        self.messages.append({"role": "user", "content": content})

    @staticmethod
    def _tool_result_output(result: Dict) -> str:
        if result.get("success"):
            content = result.get("content", "")
            if result.get("truncated"):
                content += "\n[结果已截断]"
            return content
        return "错误: " + str(result.get("error", "unknown_error"))

    def _call_model(self) -> str:
        response = self.model_callback(list(self.messages))
        if isinstance(response, str):
            if self.chunk_callback:
                self.chunk_callback(response)
            return response

        chunks = []
        try:
            iterator = iter(response)
        except TypeError:
            if self.chunk_callback:
                self.chunk_callback(str(response))
            return str(response)

        for chunk in iterator:
            if not isinstance(chunk, str):
                chunk = str(chunk)
            chunks.append(chunk)
            if self.chunk_callback:
                self.chunk_callback(chunk)
        return "".join(chunks)

    def _parse_tool_request(self, response: str):
        stripped = response.strip()
        if not stripped.startswith(TOOL_REQUEST_PREFIX):
            return None
        payload = stripped[len(TOOL_REQUEST_PREFIX):].strip()
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError:
            return "invalid"
        if not isinstance(parsed, dict):
            return "invalid"
        return parsed

    def _validate_tool_args(self, name: str, args: Dict) -> str:
        schema = self.tools.schemas()[name]
        extra = set(args) - schema["allowed"]
        if extra:
            return "invalid_tool_args"
        missing = schema["required"] - set(args)
        if missing:
            return "missing_tool_args"

        if "command" in args and not isinstance(args["command"], str):
            return "invalid_command_arg"
        for key in ("path", "content", "query", "glob"):
            if key in args and not isinstance(args[key], str):
                return f"invalid_{key}_arg"
        return ""

    @staticmethod
    def _is_direct_tool_task(task: str) -> bool:
        text = task.strip().lower()
        if not text:
            return False

        analysis_markers = (
            "分析", "梳理", "解释", "总结", "审查", "检查", "修复", "为什么", "怎么", "如何", "架构", "调用关系", "潜在",
            "analyze", "explain", "summarize", "review", "fix", "why", "how",
        )
        if any(marker in text for marker in analysis_markers):
            return False

        direct_markers = ("执行", "运行", "命令", "run", "exec", "execute")
        return any(marker in text for marker in direct_markers)

    def _direct_tool_request_from_task(self, task: str) -> Optional[Dict]:
        text = task.strip()
        if not self.direct_tool_task:
            return None
        command = self._extract_command_arg(text)
        if command:
            return {"tool": "run_command", "args": {"command": command}}
        return None

    @staticmethod
    def _extract_command_arg(task: str) -> str:
        patterns = (
            r"(?:执行命令|运行命令|执行|运行|命令|run|exec|execute)\s+(.+)$",
        )
        for pattern in patterns:
            match = re.search(pattern, task.strip(), re.IGNORECASE)
            if match:
                return match.group(1).strip().strip('"\'')
        return ""

    def _system_prompt(self) -> str:
        summary = self.config.permission_summary()
        tools = self.tools.descriptions()
        return (
            "你是 Cryptoden 的受权限控制代码 Agent。\n"
            "目标：帮助用户分析和维护当前项目代码、模块职责、调用关系和潜在问题。\n"
            "安全边界：只能请求权限摘要允许的 MCP 工具；不能删除文件；不能执行破坏性命令；不能读取敏感配置。\n"
            "行为模式：\n"
            "- 如果用户只是问问题、打招呼或询问你的身份，直接回答即可，不需要调用工具。\n"
            "- 只有当用户要求执行具体操作（如列目录、读文件、搜索文本、运行命令等）时，才使用工具。\n"
            "- 需要使用工具时，输出格式如下：\n"
            'TOOL_REQUEST: {"tool": "run_command", "args": {"command": "dir"}}\n'
            'TOOL_REQUEST: {"tool": "read_file", "args": {"path": "README.md"}}\n'
            "规则：\n"
            "1. 工具请求必须以 TOOL_REQUEST: 开头，后面是单个 JSON 对象。\n"
            "2. 输出工具请求时不要附加解释、Markdown 代码块或多个 JSON。\n"
            "3. 工具返回后，根据结果继续分析；不需要工具时直接输出最终中文报告。\n"
            "4. 优先使用 list_files/read_file/search_text/write_file/web_search 等 MCP 工具；只有确实需要时才用 run_command。\n"
            "5. 工具结果会以普通用户消息 `工具执行结果:` 回传，请把它当作本轮工具输出。\n"
            "6. 一次只请求一个工具，成功后就输出报告，不要连续请求多个工具。\n"
            "7. 当前运行在 Windows 系统，命令通过 PowerShell 执行，支持 dir/type/findstr 等传统命令以及 Get-ChildItem/Get-Content/Select-String 等 PowerShell 命令。\n"
            f"当前权限摘要: {json.dumps(summary, ensure_ascii=False)}\n"
            f"可用 MCP 工具: {json.dumps(tools, ensure_ascii=False)}"
        )

    def _result(self, status: str, output: str = "", pending_request: PermissionRequest = None) -> AgentRunResult:
        return AgentRunResult(
            status=status,
            output=output,
            messages=list(self.messages),
            pending_request=pending_request,
            tool_calls_used=self.tool_calls_used,
        )
