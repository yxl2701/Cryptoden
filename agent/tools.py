"""Tool facade for the MCP-enabled agent."""

from typing import Dict

from .config import AgentConfig
from .mcp import AgentMCPRegistry
from .policy import AgentPolicy


class AgentTools:
    def __init__(self, config: AgentConfig = None, policy: AgentPolicy = None):
        self.config = config or AgentConfig()
        self.policy = policy or AgentPolicy(self.config)
        self.mcp = AgentMCPRegistry(self.config, self.policy)

    def schemas(self) -> Dict:
        return self.mcp.schemas()

    def descriptions(self):
        return self.mcp.descriptions()

    def has_tool(self, name: str) -> bool:
        return self.mcp.has_tool(name)

    def target_for(self, name: str, args: Dict) -> str:
        return self.mcp.target_for(name, args)

    def execute(self, name: str, args: Dict) -> Dict:
        decision = self.policy.check(name, self.target_for(name, args))
        if decision.denied:
            return self._error(decision.reason)
        return self.mcp.call(name, args)

    def run_command(self, command: str) -> Dict:
        return self.execute("run_command", {"command": command})

    @staticmethod
    def _success(content: str, truncated: bool = False, decision: str = "ask") -> Dict:
        return {"success": True, "content": content, "truncated": truncated, "decision": decision, "error": ""}

    @staticmethod
    def _error(error: str) -> Dict:
        return {"success": False, "content": "", "truncated": False, "decision": "deny", "error": error}
