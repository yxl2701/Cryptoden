import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.config import AgentConfig
from agent.model import AgentModel
from agent.runtime import AgentRuntime
from agent.tools import AgentTools


class FakeConfig:
    def __init__(self):
        self.history = []

    def add_history(self, role, content):
        self.history.append({"role": role, "content": content})


class FakeAIClient:
    def __init__(self, chunks):
        self.config = FakeConfig()
        self.calls = []
        self.chunks = chunks

    def complete_messages(self, messages, stream=False, temperature=None, max_tokens=None):
        self.calls.append({
            "messages": messages,
            "stream": stream,
            "temperature": temperature,
            "max_tokens": max_tokens,
        })
        for chunk in self.chunks:
            yield chunk


def make_config_and_tools(tmp_path: Path):
    config_path = tmp_path / "agent_config.json"
    config_path.write_text(json.dumps({}), encoding="utf-8")
    config = AgentConfig(config_path=config_path, project_root=tmp_path)
    return config, AgentTools(config=config)


def test_agent_model_uses_complete_messages_without_history():
    client = FakeAIClient(["hello", " world"])
    model = AgentModel(client, temperature=0.1, max_tokens=123)

    result = model([{"role": "user", "content": "hi"}])

    assert result == "hello world"
    assert client.calls[0]["stream"] is True
    assert client.calls[0]["temperature"] == 0.1
    assert client.calls[0]["max_tokens"] == 123
    assert client.config.history == []


def test_agent_model_streams_chunks():
    client = FakeAIClient(["a", "b"])
    model = AgentModel(client)

    assert list(model.stream([{"role": "user", "content": "hi"}])) == ["a", "b"]
    assert client.calls[0]["stream"] is True


def test_runtime_with_ai_client_emits_chunks(tmp_path):
    client = FakeAIClient(["流", "式"])
    chunks = []
    config, tools = make_config_and_tools(tmp_path)
    runtime = AgentRuntime.with_ai_client(client, config=config, tools=tools, chunk_callback=chunks.append)

    result = runtime.run("分析")

    assert result.status == "completed"
    assert result.output == "流式"
    assert chunks == ["流", "式"]


def test_runtime_with_ai_client_factory(tmp_path):
    client = FakeAIClient(["这是最终报告"])
    config, tools = make_config_and_tools(tmp_path)
    runtime = AgentRuntime.with_ai_client(client, config=config, tools=tools)

    result = runtime.run("分析")

    assert result.status == "completed"
    assert result.output == "这是最终报告"
    assert client.calls
