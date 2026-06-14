"""
AI助手模块
==========
提供AI对话功能，支持API和本地模型

支持的后端:
- OpenAI API (GPT-3.5, GPT-4)
- DeepSeek API
- Ollama 本地模型
- 自定义API端点
"""

import json
import socket
import urllib.request
import urllib.error
import time
from pathlib import Path
from typing import Optional, List, Dict, Generator


AI_CONFIG_FILE = Path(__file__).parent.parent / "config" / "ai_config.json"

MODEL_ALIASES = {
    'modelscope': {
        'deepseek-v4-flash': 'deepseek-ai/DeepSeek-V4-Flash',
    },
    'deepseek': {
        'deepseek-ai/DeepSeek-V4-Flash': 'deepseek-v4-flash',
    },
}


class AIConfig:
    """AI配置管理"""
    
    DEFAULT_CONFIG = {
        'provider': 'openai',
        'api_key': '',
        'api_base': '',
        'model': 'gpt-3.5-turbo',
        'temperature': 0.7,
        'max_tokens': 2048,
        'system_prompt': '你是一个CTF加解密助手，帮助用户解决密码学问题。请用中文回答。',
        'history': [],
        'providers': {
            'openai': {
                'name': 'OpenAI',
                'api_base': 'https://api.openai.com/v1',
                'models': ['gpt-3.5-turbo', 'gpt-4', 'gpt-4-turbo', 'gpt-4o', 'gpt-4o-mini']
            },
            'deepseek': {
                'name': 'DeepSeek',
                'api_base': 'https://api.deepseek.com/v1',
                'models': ['deepseek-chat', 'deepseek-coder']
            },
            'sensenova': {
                'name': 'SenseNova (商汤)',
                'api_base': 'https://token.sensenova.cn/v1',
                'models': ['sensenova-u1-fast', 'sensenova-6.7-flash-lite']
            },
            'modelscope': {
                'name': 'ModelScope (魔塔社区)',
                'api_base': 'https://api-inference.modelscope.cn/v1',
                'models': [
                    'deepseek-ai/DeepSeek-V4-Flash',
                    'deepseek-ai/DeepSeek-R1-0528',
                    'deepseek-ai/DeepSeek-V3.2',
                    'Qwen/Qwen3-235B-A22B',
                    'Qwen/Qwen3-32B',
                    'Qwen/Qwen3-14B',
                    'Qwen/Qwen3-8B',
                    'Qwen/QwQ-32B',
                    'Qwen/QVQ-72B-Preview',
                    'Qwen/Qwen3.5-122B-A10B',
                    'ZhipuAI/GLM-5',
                    'ZhipuAI/GLM-4.7-Flash',
                    'ZhipuAI/GLM-5.1',
                    'MiniMax/MiniMax-M2.7',
                    'moonshotai/Kimi-K2.5',
                    'stepfun-ai/Step-3.5-Flash',
                    'mistralai/Mistral-Large-Instruct-2407',
                    'LLM-Research/Llama-4-Maverick-17B-128E-Instruct',
                ]
            },
            'ollama': {
                'name': 'Ollama (本地)',
                'api_base': 'http://localhost:11434/v1',
                'models': ['llama3', 'llama3:8b', 'llama3:70b', 'qwen2', 'qwen2:7b', 'codellama', 'mistral']
            },
            'custom': {
                'name': '自定义API',
                'api_base': '',
                'models': []
            }
        }
    }
    
    def __init__(self):
        self.config_path = AI_CONFIG_FILE
        self.config = self.load_config()
    
    def load_config(self) -> dict:
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    saved = json.load(f)
                    merged = self.DEFAULT_CONFIG.copy()
                    for k, v in saved.items():
                        if k != 'providers':
                            merged[k] = v
                    if 'providers' in saved:
                        for k, v in saved['providers'].items():
                            if k in merged['providers']:
                                merged['providers'][k].update(v)
                            else:
                                merged['providers'][k] = v
                    self._normalize_model_alias(merged)
                    self._resolve_provider_api_key(merged)
                    return merged
            except:
                pass
        return self.DEFAULT_CONFIG.copy()

    @staticmethod
    def _resolve_provider_api_key(config: dict):
        provider = config.get('provider', '')
        provider_api_key = config.get('providers', {}).get(provider, {}).get('api_key', '')
        if provider_api_key:
            config['api_key'] = provider_api_key

    @staticmethod
    def _normalize_model_alias(config: dict):
        provider = config.get('provider', '')
        model = config.get('model', '')
        alias = MODEL_ALIASES.get(provider, {}).get(model)
        if alias:
            config['model'] = alias

    def save_config(self):
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self._normalize_model_alias(self.config)
        self._save_api_key_to_provider()
        with open(self.config_path, 'w', encoding='utf-8') as f:
            json.dump(self.config, f, indent=2, ensure_ascii=False)
    
    def _save_api_key_to_provider(self):
        provider = self.config.get('provider', '')
        api_key = self.config.get('api_key', '')
        providers = self.config.setdefault('providers', {})
        if provider in providers:
            providers[provider]['api_key'] = api_key
    
    def get(self, key, default=None):
        return self.config.get(key, default)
    
    def set(self, key, value):
        self.config[key] = value
        if key == 'api_key':
            self._save_api_key_to_provider()
        self.save_config()
    
    def switch_provider(self, new_provider: str):
        """切换提供商，保留原提供商的 api_key，加载新提供商的 api_key。"""
        old_provider = self.config.get('provider', '')
        old_api_key = self.config.get('api_key', '')
        providers = self.config.setdefault('providers', {})
        if old_provider in providers:
            providers[old_provider]['api_key'] = old_api_key
        self.config['provider'] = new_provider
        new_api_key = providers.get(new_provider, {}).get('api_key', '')
        self.config['api_key'] = new_api_key
        self.save_config()
    
    def get_provider_config(self, provider: str) -> dict:
        return self.config.get('providers', {}).get(provider, {})
    
    def add_history(self, role: str, content: str):
        history = self.config.get('history', [])
        history.append({'role': role, 'content': content})
        if len(history) > 100:
            history = history[-100:]
        self.config['history'] = history
        self.save_config()
    
    def clear_history(self):
        self.config['history'] = []
        self.save_config()
    
    def get_history(self) -> List[dict]:
        return self.config.get('history', [])


class AIClient:
    """AI客户端"""

    REQUEST_TIMEOUT = 180
    
    def __init__(self, config: AIConfig):
        self.config = config

    def complete_messages(self, messages: List[Dict], stream: bool = False,
                          temperature: Optional[float] = None,
                          max_tokens: Optional[int] = None) -> Generator[str, None, None]:
        """
        使用完整 messages 调用模型，不写入普通聊天历史。

        Agent、自动分析等非聊天场景应使用该方法，避免污染用户对话记录。
        """
        provider = self.config.get('provider', 'openai')
        provider_config = self.config.get_provider_config(provider)

        api_key = self.config.get('api_key', '')
        api_base = self.config.get('api_base') or provider_config.get('api_base', 'https://api.openai.com/v1')
        model = self._normalized_model(provider, self.config.get('model', 'gpt-3.5-turbo'))
        temperature = self.config.get('temperature', 0.7) if temperature is None else temperature
        max_tokens = self.config.get('max_tokens', 2048) if max_tokens is None else max_tokens

        if not api_key and provider != 'ollama':
            yield "错误: 未配置API密钥，请在设置中配置。"
            return

        payload = {
            'model': model,
            'messages': messages,
            'stream': stream
        }

        if provider == 'ollama':
            payload['options'] = {
                'temperature': temperature,
                'num_predict': max_tokens
            }
        else:
            payload['temperature'] = temperature
            payload['max_tokens'] = max_tokens

        headers = {'Content-Type': 'application/json'}
        if api_key:
            headers['Authorization'] = f'Bearer {api_key}'

        url = f"{api_base.rstrip('/')}/chat/completions"

        try:
            data = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(url, data=data, headers=headers, method='POST')

            if stream:
                yield from self._handle_stream_response(req, save_history=False)
            else:
                yield from self._handle_normal_response(req, save_history=False)

        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8', errors='replace')
            yield self._format_http_error(e.code, error_body, provider, model)
        except urllib.error.URLError as e:
            if provider == 'ollama':
                yield f"无法连接到Ollama服务: {str(e)}\n请确保Ollama正在运行 (ollama serve)"
            else:
                yield f"网络错误: {str(e)}"
        except socket.timeout:
            yield "请求超时：模型长时间未返回结果。请稍后重试，或切换更快的模型。"
        except Exception as e:
            yield f"请求失败: {str(e)}"
    
    def chat(self, message: str, stream: bool = False, system_prompt: str = None,
              max_retries: int = 2) -> Generator[str, None, None]:
        """
        AI对话（支持自动重试）
        
        参数:
            message: 用户消息
            stream: 是否流式输出
            system_prompt: 系统提示词（覆盖默认）
            max_retries: 失败重试次数（对429限流自动重试）
        """
        for attempt in range(max_retries + 1):
            try:
                yield from self._chat_openai_compatible(message, stream, system_prompt)
                return  # 成功则退出
            except Exception as e:
                error_msg = str(e)
                # 429限流: 自动重试
                if '429' in error_msg and attempt < max_retries:
                    wait = (attempt + 1) * 2  # 2s, 4s
                    yield f"\n[限流，{wait}秒后重试...]\n"
                    time.sleep(wait)
                    continue
                # 其他错误或已达最大重试次数
                if attempt == max_retries:
                    yield f"\n[错误: {error_msg}]\n"
                else:
                    yield f"\n[重试中... ({attempt+1}/{max_retries})]\n"
                    time.sleep(1)
    
    def _chat_openai_compatible(self, message: str, stream: bool = False, system_prompt: str = None) -> Generator[str, None, None]:
        # 优先使用传入的系统提示词，否则使用配置中的默认提示词
        if system_prompt is None:
            system_prompt = self.config.get('system_prompt', '')

        messages = []
        if system_prompt:
            messages.append({'role': 'system', 'content': system_prompt})

        messages.extend(self.config.get_history())
        messages.append({'role': 'user', 'content': message})

        self._last_response_content = ''
        for chunk in self.complete_messages(messages, stream=stream):
            yield chunk

        content = getattr(self, '_last_response_content', '')
        if content:
            self.config.add_history('user', message)
            self.config.add_history('assistant', content)

    def _handle_normal_response(self, req, save_history: bool = False) -> Generator[str, None, None]:
        with urllib.request.urlopen(req, timeout=self.REQUEST_TIMEOUT) as response:
            result = json.loads(response.read().decode('utf-8'))
            
            if 'choices' in result and len(result['choices']) > 0:
                content = result['choices'][0].get('message', {}).get('content', '')
                self._last_response_content = content
                yield content
            else:
                yield f"意外的响应格式: {result}"
    
    def _handle_stream_response(self, req, save_history: bool = False) -> Generator[str, None, None]:
        full_content = ""
        try:
            with urllib.request.urlopen(req, timeout=self.REQUEST_TIMEOUT) as response:
                for line in response:
                    line = line.decode('utf-8').strip()
                    if line.startswith('data: '):
                        data = line[6:]
                        if data == '[DONE]':
                            break
                        try:
                            chunk = json.loads(data)
                            if 'choices' in chunk and len(chunk['choices']) > 0:
                                delta = chunk['choices'][0].get('delta', {})
                                content = delta.get('content', '')
                                if content:
                                    full_content += content
                                    yield content
                        except json.JSONDecodeError:
                            continue
            
            self._last_response_content = full_content
                
        except urllib.error.HTTPError as e:
            body = e.read().decode('utf-8', errors='replace')
            if e.code == 429:
                yield "\n模型接口限流或额度不足 (HTTP 429)。请稍后重试，或在 AI 设置中切换模型/API Key。"
            else:
                yield "\n" + self._format_http_error(e.code, body, self.config.get('provider', ''), self.config.get('model', ''))
        except socket.timeout:
            yield "\n请求超时：模型长时间未返回结果。请稍后重试，或切换更快的模型。"
        except Exception as e:
            yield f"\n流式响应错误: {str(e)}"

    @staticmethod
    def _normalized_model(provider: str, model: str) -> str:
        return MODEL_ALIASES.get(provider, {}).get(model, model)

    @staticmethod
    def _format_http_error(code: int, body: str, provider: str, model: str) -> str:
        lowered = body.lower()
        if code == 400 and 'invalid model' in lowered:
            alias = MODEL_ALIASES.get(provider, {}).get(model)
            suggestion = f"，可尝试改为 `{alias}`" if alias else "，请在 AI 设置中刷新模型列表并选择当前平台返回的模型 ID"
            return f"模型配置错误 (HTTP 400)：当前模型 `{model}` 无效{suggestion}。原始响应: {body}"
        return f"API错误 ({code}): {body}"
    
    def test_connection(self) -> tuple:
        provider = self.config.get('provider', 'openai')
        provider_config = self.config.get_provider_config(provider)
        
        api_key = self.config.get('api_key', '')
        api_base = self.config.get('api_base') or provider_config.get('api_base', '')
        model = self.config.get('model', '')
        
        if not api_base:
            return False, "未配置API地址"
        
        if not api_key and provider not in ['ollama']:
            return False, "未配置API密钥"
        
        if not model:
            return False, "未选择模型"
        
        headers = {'Content-Type': 'application/json'}
        if api_key:
            headers['Authorization'] = f'Bearer {api_key}'
        
        url = f"{api_base.rstrip('/')}/models"
        
        try:
            req = urllib.request.Request(url, headers=headers, method='GET')
            with urllib.request.urlopen(req, timeout=10) as response:
                return True, "连接成功"
        except urllib.error.HTTPError as e:
            if e.code == 401:
                return False, "API密钥无效"
            return False, f"HTTP错误: {e.code}"
        except urllib.error.URLError as e:
            return False, f"无法连接: {str(e)}"
        except Exception as e:
            return False, f"连接失败: {str(e)}"


def get_available_models(provider: str, api_base: str = None, api_key: str = None) -> List[str]:
    """
    获取可用模型列表
    
    支持 OpenAI 兼容接口和 SenseNova 等不同 API 格式。
    如果无法获取在线列表，返回空列表，由界面保留手动输入能力。
    """
    config = AIConfig()
    provider_config = config.get_provider_config(provider)
    
    # 只在明确提供了 API 密钥或 base_url 时才尝试获取在线列表
    if api_key is None and api_base is None:
        return []
    
    base_url = api_base if api_base is not None else provider_config.get('api_base', '')
    key = api_key if api_key is not None else config.get('api_key', '')
    
    if not base_url:
        return []
    
    # 没有 API 密钥且不是本地模型时，不尝试网络请求
    if not key and provider != 'ollama':
        return []
    
    headers = {'Content-Type': 'application/json'}
    if key:
        headers['Authorization'] = f'Bearer {key}'
    
    # 不同提供商可能有不同的模型列表接口
    endpoints = []
    endpoints.append(f"{base_url.rstrip('/')}/models")
    
    # 有些服务使用不同的路径
    alt_base = base_url.rstrip('/')
    if '/v1' in alt_base:
        endpoints.append(alt_base.replace('/v1', '/api/models'))
    
    for url in endpoints:
        try:
            req = urllib.request.Request(url, headers=headers, method='GET')
            with urllib.request.urlopen(req, timeout=5) as response:
                result = json.loads(response.read().decode('utf-8'))
                
                # 尝试多种 JSON 格式解析
                models = []
                if 'data' in result:
                    # OpenAI 格式: {"data": [{"id": "model-name", ...}]}
                    for m in result['data']:
                        if isinstance(m, dict):
                            mid = m.get('id') or m.get('name') or ''
                            if mid:
                                models.append(mid)
                        elif isinstance(m, str):
                            models.append(m)
                elif isinstance(result, list):
                    for m in result:
                        if isinstance(m, dict):
                            mid = m.get('id') or m.get('name') or ''
                            if mid:
                                models.append(mid)
                        elif isinstance(m, str):
                            models.append(m)
                elif 'models' in result:
                    models = result['models']
                
                if models:
                    return models
        except Exception:
            continue
    
    return []
