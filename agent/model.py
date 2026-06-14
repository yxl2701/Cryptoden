"""Model adapters for the restricted agent runtime."""

from typing import Dict, List

from utils.ai_assistant import AIClient, AIConfig


class AgentModel:
    """Small adapter that makes AIClient usable as an AgentRuntime callback."""

    def __init__(self, client: AIClient = None, temperature: float = 0.2, max_tokens: int = None):
        self.config = AIConfig() if client is None else client.config
        self.client = client or AIClient(self.config)
        self.temperature = temperature
        self.max_tokens = max_tokens

    def complete(self, messages: List[Dict]) -> str:
        return "".join(self.stream(messages))

    def stream(self, messages: List[Dict]):
        chunks = self.client.complete_messages(
            messages,
            stream=True,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )
        yield from chunks

    def __call__(self, messages: List[Dict]) -> str:
        return self.complete(messages)
