# Cryptoden Agent

Cryptoden Agent 是 AI 工作台中的受限代码分析模式，用于辅助理解、分析和审查当前项目代码。

## 使用场景

- 梳理项目结构和模块职责。
- 搜索代码位置和调用关系。
- 总结文件、类、函数的作用。
- 识别潜在风险、重复逻辑和异常处理问题。
- 生成分析报告。
- 在用户确认后执行有限写入、网络搜索或外部 MCP 工具调用。

## 安全边界

- 默认遵循本地权限策略，所有工具请求都必须经过 `AgentPolicy`。
- 当前默认权限模式为 `command`，内置 MCP 工具可读取/搜索工作空间、网络搜索、执行白名单命令，并在写文件、联网或外部 MCP 调用前请求确认。
- 路径会归一化为绝对路径，并限制在当前工作空间内。
- `search_text` 可以独立启用，不依赖 `read_file` 工具开关，但仍会执行工作空间和敏感路径检查。
- Agent 不能读取 API Key、`.env`、凭据文件等敏感内容。
- Agent 不能读取 `agent/agent_config.json` 全文。
- Agent 不能修改权限配置、安全核心实现或 AI 配置文件。
- 危险命令和访问项目外路径会被拒绝。

## 权限配置

配置文件：`agent/agent_config.json`

主要字段：

- `permission_mode`：权限模式，当前实现默认值为 `command`。
- `require_confirmation_for_command`：命令执行是否需要确认。
- `require_confirmation_for_mcp`：写文件、网络搜索、外部 MCP 调用是否需要确认。
- `enabled_command_tools`：允许启用的命令工具列表。
- `enabled_mcp_tools`：允许启用的 MCP 工具列表，内置工具包括 `list_files`、`read_file`、`write_file`、`search_text`、`web_search`、`run_command`。
- `mcp_servers`：用户自定义 MCP 配置。工具名以 `服务名.工具名` 形式加入 `enabled_mcp_tools` 后可被 Agent 调用。
- `allowed_commands`：白名单命令。
- `max_tool_calls`：单次任务工具调用预算。

当前默认白名单示例包括 `pytest`、`python cli.py list`、`python cli.py --version`。允许项仍会经过危险命令过滤。

用户自定义 MCP 示例：

```json
{
  "mcp_servers": {
    "notes": {
      "enabled": true,
      "command": "python",
      "args": ["tools/notes_mcp.py"],
      "tools": [
        {
          "name": "lookup",
          "description": "查询本地笔记",
          "required_args": ["query"],
          "allowed_args": ["query"]
        }
      ]
    }
  },
  "enabled_mcp_tools": ["read_file", "search_text", "notes.lookup"]
}
```

外部 MCP 当前通过 stdio 调用，程序会向进程 stdin 写入 `tools/call` JSON-RPC 请求，并读取 stdout 作为工具结果。

请求格式示例：

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lookup","arguments":{"query":"rsa"}}}
```

支持的返回格式示例：

```json
{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"查询结果"}]}}
```

如果返回 `error`，或 `result.isError` 为 `true`，Agent 会把该结果视为工具失败。

## GUI 行为

- 入口：`AI工作台 -> Agent模式`。
- 用户输入任务后，Agent 根据模型输出生成工具请求。
- 执行命令、写文件、联网搜索或调用外部 MCP 前，界面会显示请求摘要，用户可选择 `允许一次` 或 `拒绝`。
- 输出区只展示分析过程和结果，不展示敏感配置全文。

## 开发约定

- 新工具必须先接入 `AgentPolicy`，不能绕过权限层。
- 文件工具必须做工作空间边界检查和敏感路径检查。
- 命令工具必须遵守白名单和危险命令拦截。
- 外部 MCP 工具必须在 `mcp_servers` 中声明，并在 `enabled_mcp_tools` 中显式启用。
- 测试应覆盖权限配置、策略拒绝、工具边界、外部 MCP 返回解析和运行时预算。

## 验证

```bash
python -m pytest tests/test_agent_config.py tests/test_agent_policy.py tests/test_agent_tools.py tests/test_agent_permission_request.py tests/test_agent_runtime.py
```
