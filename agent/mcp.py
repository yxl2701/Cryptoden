"""Lightweight MCP-style tool registry for the agent."""

import fnmatch
import json
import os
import subprocess
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    allowed: set
    required: set
    runner: Callable[[Dict], Dict]
    target: Callable[[Dict], str]
    external: bool = False


class AgentMCPRegistry:
    """Register built-in tools and user configured stdio MCP tools."""

    def __init__(self, config, policy):
        self.config = config
        self.policy = policy
        self.tools: Dict[str, ToolSpec] = {}
        self._register_builtin_tools()
        self._register_external_tools()

    def schemas(self) -> Dict[str, Dict[str, set]]:
        return {name: {"allowed": spec.allowed, "required": spec.required} for name, spec in self.tools.items()}

    def descriptions(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": spec.name,
                "description": spec.description,
                "required_args": sorted(spec.required),
                "allowed_args": sorted(spec.allowed),
                "external": spec.external,
            }
            for spec in self.tools.values()
        ]

    def has_tool(self, name: str) -> bool:
        return name in self.tools

    def target_for(self, name: str, args: Dict) -> str:
        spec = self.tools.get(name)
        return spec.target(args) if spec else "."

    def call(self, name: str, args: Dict) -> Dict:
        spec = self.tools.get(name)
        if not spec:
            return self._error("invalid_tool")
        return spec.runner(args)

    def _register(self, spec: ToolSpec):
        if spec.name in self.config.get("enabled_mcp_tools", []) or spec.name == "run_command":
            self.tools[spec.name] = spec

    def _register_builtin_tools(self):
        self._register(ToolSpec("run_command", "执行本地命令，沿用命令白名单和用户确认策略。", {"command"}, {"command"}, lambda args: self._run_command(args.get("command", "")), lambda args: args.get("command", "")))
        self._register(ToolSpec("list_files", "列出工作空间内目录内容。", {"path"}, set(), lambda args: self._list_files(args.get("path", ".")), lambda args: args.get("path", ".")))
        self._register(ToolSpec("read_file", "读取工作空间内非敏感文件。", {"path"}, {"path"}, lambda args: self._read_file(args.get("path", "")), lambda args: args.get("path", "")))
        self._register(ToolSpec("write_file", "写入工作空间内非受保护文件，需要用户确认。", {"path", "content"}, {"path", "content"}, lambda args: self._write_file(args.get("path", ""), args.get("content", "")), lambda args: args.get("path", "")))
        self._register(ToolSpec("search_text", "在工作空间内按文本或通配文件名搜索。", {"query", "path", "glob"}, {"query"}, lambda args: self._search_text(args.get("query", ""), args.get("path", "."), args.get("glob", "*")), lambda args: args.get("path", ".")))
        self._register(ToolSpec("web_search", "通过 DuckDuckGo Lite 进行网络搜索并返回摘要。", {"query"}, {"query"}, lambda args: self._web_search(args.get("query", "")), lambda args: args.get("query", "")))

    def _register_external_tools(self):
        servers = self.config.get("mcp_servers", {})
        if not isinstance(servers, dict):
            return
        for server_name, server in servers.items():
            if not isinstance(server, dict) or not server.get("enabled", True):
                continue
            tools = server.get("tools", [])
            if not isinstance(tools, list):
                continue
            for tool in tools:
                if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
                    continue
                full_name = f"{server_name}.{tool['name']}"
                allowed = set(tool.get("allowed_args") or [])
                required = set(tool.get("required_args") or [])
                if not allowed:
                    allowed = set(required)
                self._register(ToolSpec(full_name, tool.get("description", "用户自定义 MCP 工具"), allowed, required, lambda args, s=server, t=tool["name"]: self._call_stdio_mcp(s, t, args), lambda args, n=full_name: n, external=True))

    def _run_command(self, command: str) -> Dict:
        if not isinstance(command, str) or not command.strip():
            return self._error("invalid_command")
        command = command.strip()
        decision = self.policy.check("run_command", command)
        if decision.denied:
            return self._error(decision.reason)
        try:
            if os.name == "nt":
                proc = subprocess.run(["powershell", "-NoProfile", "-Command", command], cwd=self.policy.workspace_root, text=True, capture_output=True, timeout=30, check=False)
            else:
                proc = subprocess.run(command.split(), cwd=self.policy.workspace_root, text=True, capture_output=True, timeout=30, check=False)
        except subprocess.TimeoutExpired:
            return self._error("command_timeout")
        except Exception as exc:
            return self._error(f"command_failed: {exc}")
        output = proc.stdout
        if proc.stderr:
            output += ("\n" if output else "") + proc.stderr
        if not output:
            output = f"命令完成，退出码 {proc.returncode}" if proc.returncode == 0 else f"命令失败，退出码 {proc.returncode}"
        return self._success_limited(output, decision=decision.decision)

    def _list_files(self, path: str) -> Dict:
        target = self._safe_path(path or ".")
        if isinstance(target, dict):
            return target
        if not target.exists():
            return self._error("path_not_found")
        if not target.is_dir():
            return self._error("not_a_directory")
        entries = []
        for child in sorted(target.iterdir(), key=lambda item: item.name.lower()):
            rel = self._relative(child)
            if self._is_ignored(rel, self.config.get("ignored_paths", [])):
                continue
            entries.append(rel + ("/" if child.is_dir() else ""))
            if len(entries) >= self.config.get("max_list_entries"):
                break
        return self._success("\n".join(entries))

    def _read_file(self, path: str) -> Dict:
        target = self._safe_path(path)
        if isinstance(target, dict):
            return target
        if not target.exists():
            return self._error("path_not_found")
        if not target.is_file():
            return self._error("not_a_file")
        if target.stat().st_size > self.config.get("max_read_file_bytes"):
            return self._error("file_too_large")
        try:
            return self._success_limited(target.read_text(encoding="utf-8", errors="replace"))
        except Exception as exc:
            return self._error(f"read_failed: {exc}")

    def _write_file(self, path: str, content: str) -> Dict:
        if not isinstance(content, str):
            return self._error("invalid_content")
        target = self._safe_path(path)
        if isinstance(target, dict):
            return target
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        except Exception as exc:
            return self._error(f"write_failed: {exc}")
        return self._success(f"写入完成: {self._relative(target)}")

    def _search_text(self, query: str, path: str = ".", glob: str = "*") -> Dict:
        if not isinstance(query, str) or not query:
            return self._error("invalid_query")
        root = self._safe_path(path or ".")
        if isinstance(root, dict):
            return root
        files = [root] if root.is_file() else [item for item in root.rglob("*") if item.is_file()]
        results = []
        for file_path in files:
            rel = self._relative(file_path)
            if self._is_ignored(rel, self.config.get("ignored_paths", [])) or not fnmatch.fnmatch(file_path.name, glob or "*"):
                continue
            if self.policy.check_workspace_path(rel).denied:
                continue
            try:
                for number, line in enumerate(file_path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
                    if query in line:
                        results.append(f"{rel}:{number}: {line[:500]}")
                        if len(results) >= self.config.get("max_search_results"):
                            return self._success_limited("\n".join(results))
            except Exception:
                continue
        return self._success_limited("\n".join(results) if results else "未找到匹配结果")

    def _web_search(self, query: str) -> Dict:
        if not isinstance(query, str) or not query.strip():
            return self._error("invalid_query")
        url = "https://duckduckgo.com/html/?" + urllib.parse.urlencode({"q": query.strip()})
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Cryptoden-Agent/1.0"})
            with urllib.request.urlopen(req, timeout=15) as response:
                html = response.read().decode("utf-8", errors="replace")
        except Exception as exc:
            return self._error(f"web_search_failed: {exc}")
        text = html.replace("</a>", "\n").replace("</div>", "\n")
        text = "\n".join(line.strip() for line in text.splitlines() if line.strip())
        return self._success_limited(text)

    def _call_stdio_mcp(self, server: Dict, tool_name: str, args: Dict) -> Dict:
        command = server.get("command")
        command_args = server.get("args", [])
        server_env = server.get("env", {})
        if not isinstance(command, str) or not command:
            return self._error("invalid_mcp_server_command")
        if not isinstance(command_args, list):
            command_args = []
        if not isinstance(server_env, dict):
            server_env = {}
        env = dict(os.environ)
        env.update({str(key): str(value) for key, value in server_env.items()})
        request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool_name, "arguments": args}}
        try:
            proc = subprocess.run([command] + [str(item) for item in command_args], input=json.dumps(request, ensure_ascii=False) + "\n", text=True, capture_output=True, timeout=int(server.get("timeout", 30)), cwd=self.policy.workspace_root, env=env, check=False)
        except Exception as exc:
            return self._error(f"mcp_call_failed: {exc}")
        output = proc.stdout.strip() or proc.stderr.strip()
        if not output:
            return self._error(f"mcp_empty_response: {proc.returncode}")
        parsed = self._format_mcp_response(output)
        if parsed.get("error"):
            return self._error(parsed["error"])
        return self._success_limited(parsed.get("content", output))

    def _format_mcp_response(self, output: str) -> Dict:
        payload = self._parse_json_response(output)
        if payload is None:
            return {"content": output}
        if isinstance(payload.get("error"), dict):
            message = payload["error"].get("message") or payload["error"].get("code") or "mcp_error"
            return {"error": str(message)}
        result = payload.get("result")
        if isinstance(result, dict):
            if result.get("isError"):
                content_error = self._content_text(result.get("content"))
                return {"error": content_error or json.dumps(result, ensure_ascii=False)}
            content = result.get("content")
            if isinstance(content, list):
                parts = self._content_parts(content)
                if parts:
                    return {"content": "\n".join(parts)}
            if "structuredContent" in result:
                return {"content": json.dumps(result["structuredContent"], ensure_ascii=False)}
            return {"content": json.dumps(result, ensure_ascii=False)}
        if result is not None:
            return {"content": str(result)}
        return {"content": json.dumps(payload, ensure_ascii=False)}

    def _content_text(self, content) -> str:
        if not isinstance(content, list):
            return ""
        return "\n".join(self._content_parts(content))

    @staticmethod
    def _content_parts(content: List) -> List[str]:
        parts = []
        for item in content:
            if isinstance(item, dict):
                if isinstance(item.get("text"), str):
                    parts.append(item["text"])
                elif "data" in item:
                    parts.append(json.dumps(item["data"], ensure_ascii=False))
            elif isinstance(item, str):
                parts.append(item)
        return parts

    @staticmethod
    def _parse_json_response(output: str):
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            pass
        for line in reversed(output.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
        return None

    def _safe_path(self, path: str):
        decision = self.policy.check_workspace_path(path)
        if decision.denied:
            return self._error(decision.reason)
        candidate = Path(path or ".")
        if not candidate.is_absolute():
            candidate = self.policy.workspace_root / candidate
        try:
            candidate = candidate.resolve()
            candidate.relative_to(self.policy.workspace_root)
        except Exception:
            return self._error("path_outside_workspace")
        return candidate

    def _relative(self, path: Path) -> str:
        return str(path.resolve().relative_to(self.policy.workspace_root)).replace("\\", "/")

    @staticmethod
    def _is_ignored(path: str, patterns: List[str]) -> bool:
        parts = path.replace("\\", "/").split("/")
        for pattern in patterns:
            if any(fnmatch.fnmatch(part, pattern) for part in parts) or fnmatch.fnmatch(path, pattern):
                return True
        return False

    def _success_limited(self, content: str, decision: str = "allow") -> Dict:
        limit = self.config.get("max_single_tool_result_chars")
        truncated = len(content) > limit
        if truncated:
            content = content[:limit]
        return self._success(content, truncated=truncated, decision=decision)

    @staticmethod
    def _success(content: str, truncated: bool = False, decision: str = "allow") -> Dict:
        return {"success": True, "content": content, "truncated": truncated, "decision": decision, "error": ""}

    @staticmethod
    def _error(error: str) -> Dict:
        return {"success": False, "content": "", "truncated": False, "decision": "deny", "error": error}
