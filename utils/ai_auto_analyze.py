"""
AI自动分析模块
==============
当用户输入内容时，自动分析密文类型并推荐解密方法

功能:
- 自动识别编码类型 (Base64, Base32, Hex, URL, Unicode等)
- 自动识别古典密码 (凯撒, 栅栏, 埃特巴什等)
- AI智能分析复杂密文
- 自动执行推荐的解密方法
"""

import re
import json
from typing import Optional, List, Dict, Tuple
from threading import Thread
from PyQt5.QtCore import QObject, pyqtSignal

from utils.ai_assistant import AI_CONFIG_FILE, AIConfig, AIClient


class PatternAnalyzer:
    """基于规则的密文模式分析器"""
    
    BASE64_PATTERN = re.compile(r'^[A-Za-z0-9+/]+=*$')
    BASE32_PATTERN = re.compile(r'^[A-Z2-7]+=*$')
    HEX_PATTERN = re.compile(r'^[0-9a-fA-F]+$')
    MORSE_PATTERN = re.compile(r'^[.\-/\s]+$')
    BACON_PATTERN = re.compile(r'^[ABab\s]+$')
    BINARY_PATTERN = re.compile(r'^[01\s]+$')
    URL_ENCODED_PATTERN = re.compile(r'%[0-9a-fA-F]{2}')
    UNICODE_PATTERN = re.compile(r'(\\u[0-9a-fA-F]{4}|&#\d+;|&#x[0-9a-fA-F]+;)')
    
    @classmethod
    def analyze(cls, text: str) -> List[Dict]:
        results = []
        text = text.strip()
        
        if not text:
            return results
        
        text_no_space = text.replace(' ', '').replace('\n', '').replace('\r', '')
        
        if cls.BASE64_PATTERN.match(text_no_space) and len(text_no_space) >= 4:
            if text_no_space.endswith('=='):
                confidence = 0.95
            elif text_no_space.endswith('='):
                confidence = 0.9
            else:
                confidence = 0.7
            results.append({
                'type': 'Base64',
                'algorithm': 'base64',
                'category': 'decoding',
                'confidence': confidence,
                'description': 'Base64编码特征：由大小写字母、数字、+和/组成，可能以=结尾'
            })
        
        if cls.BASE32_PATTERN.match(text_no_space.upper()) and len(text_no_space) >= 8:
            results.append({
                'type': 'Base32',
                'algorithm': 'base32',
                'category': 'decoding',
                'confidence': 0.85,
                'description': 'Base32编码特征：由大写字母A-Z和数字2-7组成'
            })
        
        if cls.HEX_PATTERN.match(text_no_space) and len(text_no_space) >= 2:
            if len(text_no_space) % 2 == 0:
                results.append({
                    'type': 'Hex',
                    'algorithm': 'hex',
                    'category': 'decoding',
                    'confidence': 0.8,
                    'description': '十六进制编码特征：由0-9和a-f/A-F组成，长度为偶数'
                })
        
        if cls.MORSE_PATTERN.match(text.strip()):
            results.append({
                'type': 'Morse',
                'algorithm': 'morse摩斯密码',
                'category': 'decoding',
                'confidence': 0.9,
                'description': '摩斯密码特征：由点(.)、划(-)和空格组成'
            })
        
        if cls.BACON_PATTERN.match(text.upper().replace(' ', '')):
            bacon_text = text.upper().replace(' ', '')
            if len(bacon_text) % 5 == 0 and len(bacon_text) >= 5:
                results.append({
                    'type': 'Bacon',
                    'algorithm': 'bacon培根密码',
                    'category': 'classical',
                    'confidence': 0.75,
                    'description': '培根密码特征：由A和B组成，每5个字母编码一个字符'
                })
        
        if cls.BINARY_PATTERN.match(text.replace(' ', '')):
            binary_only = text.replace(' ', '')
            if len(binary_only) % 8 == 0 and len(binary_only) >= 8:
                results.append({
                    'type': 'Binary',
                    'algorithm': 'binary',
                    'category': 'decoding',
                    'confidence': 0.8,
                    'description': '二进制编码特征：由0和1组成，每8位表示一个字符'
                })
        
        if cls.URL_ENCODED_PATTERN.search(text):
            count = len(cls.URL_ENCODED_PATTERN.findall(text))
            results.append({
                'type': 'URL',
                'algorithm': 'url',
                'category': 'decoding',
                'confidence': min(0.9, 0.5 + count * 0.1),
                'description': 'URL编码特征：包含%XX格式的编码'
            })
        
        if cls.UNICODE_PATTERN.search(text):
            results.append({
                'type': 'Unicode',
                'algorithm': 'unicode',
                'category': 'decoding',
                'confidence': 0.85,
                'description': 'Unicode编码特征：包含\\uXXXX或&#XXXX;格式'
            })
        
        if text.isalpha() or (text.replace(' ', '').isalpha() and len(text.replace(' ', '')) > 10):
            letter_freq = cls._calc_letter_frequency(text)
            text_clean = text.replace(' ', '').upper()
            
            if cls._is_likely_caesar(letter_freq):
                results.append({
                    'type': 'Caesar',
                    'algorithm': 'caesar凯撒密码',
                    'category': 'classical',
                    'confidence': 0.6,
                    'description': '凯撒密码特征：纯字母文本，可能是字母偏移加密'
                })
            
            if cls._is_likely_atbash(text_clean):
                results.append({
                    'type': 'Atbash',
                    'algorithm': 'atbash埃特巴什码',
                    'category': 'classical',
                    'confidence': 0.5,
                    'description': '埃特巴什码特征：字母表反转替换'
                })
            
            if cls._is_likely_railfence(text_clean):
                results.append({
                    'type': 'RailFence',
                    'algorithm': 'railfence栅栏密码',
                    'category': 'classical',
                    'confidence': 0.4,
                    'description': '栅栏密码特征：换位密码，字母重新排列'
                })
        
        if '=' in text and not text.endswith('='):
            results.append({
                'type': 'ROT13',
                'algorithm': 'rot13',
                'category': 'classical',
                'confidence': 0.3,
                'description': '可能是ROT13加密'
            })
        
        return results
    
    @staticmethod
    def _calc_letter_frequency(text: str) -> Dict[str, float]:
        text = text.upper()
        letters = [c for c in text if c.isalpha()]
        if not letters:
            return {}
        
        freq = {}
        for c in letters:
            freq[c] = freq.get(c, 0) + 1
        
        total = len(letters)
        for c in freq:
            freq[c] = freq[c] / total
        
        return freq
    
    @staticmethod
    def _is_likely_caesar(freq: Dict[str, float]) -> bool:
        if not freq:
            return False
        
        english_freq = ['E', 'T', 'A', 'O', 'I', 'N', 'S', 'H', 'R']
        
        sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)
        top_letters = [l for l, f in sorted_freq[:5]]
        
        for letter in english_freq[:3]:
            if letter in top_letters:
                return True
        
        return False
    
    @staticmethod
    def _is_likely_atbash(text: str) -> bool:
        return len(text) > 5
    
    @staticmethod
    def _is_likely_railfence(text: str) -> bool:
        return len(text) > 8


class AIAutoAnalyzer(QObject):
    """AI自动分析器 - 使用AI进行智能分析"""
    
    analysis_complete = pyqtSignal(dict)
    analysis_error = pyqtSignal(str)
    analysis_chunk = pyqtSignal(str)
    
    ANALYSIS_PROMPT = """你是一个密码学专家。请分析以下密文，判断可能的加密/编码类型。

密文内容:
{ciphertext}

请逐步分析并返回结果：
1. 首先分析密文的特征（字符组成、长度、格式等）
2. 然后判断可能的加密/编码类型
3. 最后给出推荐的解密算法和置信度

请以JSON格式返回分析结果，格式如下:
{{
    "detected_type": "检测到的类型名称",
    "confidence": 0.0-1.0的置信度,
    "algorithm": "推荐的解密算法名称",
    "category": "分类(classical/encoding/symmetric/hash)",
    "description": "分析说明",
    "possible_algorithms": ["其他可能的算法列表"],
    "suggested_params": {{"参数名": "建议值"}}
}}

只返回JSON，不要其他内容。

支持的算法:
- 古典密码: caesar凯撒密码, rot13, affine仿射密码, atbash埃特巴什码, vigenere维吉尼亚密码, railfence栅栏密码, playfair普莱费尔密码, bacon培根密码, morse摩斯密码, hill希尔密码, polybius波利比乌斯密码
- 编码: base64, base32, hex, url, unicode, html
- 对称密码: xor, aes, des, blowfish, rc4
- 古典密码: caesar凯撒密码, rot13, atbash埃特巴什码, railfence栅栏密码, vigenere维吉尼亚密码, affine仿射密码
- 其他: 如果无法确定类型，请给出最可能的几种猜测

注意：
1. algorithm字段必须是具体的算法名称，便于程序调用
2. 如果是凯撒密码，suggested_params可以包含shift的建议值
3. 如果无法确定，confidence设为较低值"""

    # 算法上下文相关的分析提示词
    CONTEXT_PROMPTS = {
        'rsa': """你是一个CTF密码学专家，正在分析一个RSA加密问题。

已知信息:
{ciphertext}

请逐步分析：
1. 检查模数n的大小和特征
2. 分析公钥指数e是否特殊（小指数、大指数等）
3. 判断是否有已知的RSA攻击面（Wiener、Fermat、共模等）
4. 给出推荐的攻击方法和参数

请用中文详细回答，展示数学推导过程。""",
        'ecc': """你是一个CTF密码学专家，正在分析一个ECC（椭圆曲线）问题。

已知信息:
{ciphertext}

请逐步分析：
1. 检查曲线参数是否标准
2. 判断是否有nonce重用或参数泄露
3. 分析是否可以使用Smart攻击、Invalid Curve攻击等

请用中文详细回答。""",
        'classical': """你是一个CTF密码学专家，正在分析一段古典密码密文。

密文内容:
{ciphertext}

请逐步分析：
1. 密文的字符组成和长度特征
2. 是否包含明显的模式（重复、频率分布等）
3. 可能使用的古典密码类型
4. 建议的解密方法

请用中文详细回答。""",
        'default': """你是一个密码学专家。请分析以下密文，判断可能的加密/编码类型。

密文内容:
{ciphertext}

请逐步分析，先输出你的思考过程，最后以JSON格式返回分析结果。

分析时请按以下步骤：
1. 观察密文的字符组成和格式特征
2. 分析可能的编码或加密方式
3. 给出最可能的解密算法建议

最后请以JSON格式返回（必须包含在代码块中）：
```json
{{
    "detected_type": "检测到的类型名称",
    "confidence": 0.0-1.0的置信度,
    "algorithm": "推荐的解密算法名称",
    "category": "分类(classical/encoding/symmetric/hash)",
    "description": "分析说明",
    "possible_algorithms": ["其他可能的算法"],
    "suggested_params": {{}}
}}
```"""
    }
    
    STREAMING_PROMPT = None  # 在 __init__ 中初始化
    
    @staticmethod
    def get_context_prompt(text: str, context: str = 'default') -> str:
        """
        根据上下文获取针对性的分析提示词
        
        参数:
            text: 待分析文本
            context: 上下文类型 ('rsa', 'ecc', 'classical', 'default')
        
        返回:
            str: 填充后的提示词
        """
        template = AIAutoAnalyzer.CONTEXT_PROMPTS.get(
            context, AIAutoAnalyzer.CONTEXT_PROMPTS['default']
        )
        return template.format(ciphertext=text[:1000])
    
    def __init__(self):
        super().__init__()
        self.config = AIConfig()
        self.client = AIClient(self.config)
        if AIAutoAnalyzer.STREAMING_PROMPT is None:
            AIAutoAnalyzer.STREAMING_PROMPT = AIAutoAnalyzer.CONTEXT_PROMPTS['default']
        self._thread = None
        self._running = False
    
    def analyze_async(self, text: str, context: str = 'default'):
        """
        异步分析密文
        
        参数:
            text: 待分析文本
            context: 分析上下文 ('default', 'rsa', 'ecc', 'classical')
        """
        if self._thread and self._thread.is_alive():
            return
        
        self._running = True
        self._analysis_context = context
        self._thread = Thread(target=self._do_analysis, args=(text,))
        self._thread.daemon = True
        self._thread.start()
    
    def stop(self):
        """停止分析"""
        self._running = False
    
    def _do_analysis(self, text: str):
        try:
            pattern_results = PatternAnalyzer.analyze(text)
            
            if pattern_results:
                best_result = max(pattern_results, key=lambda x: x['confidence'])
                if best_result['confidence'] >= 0.8:
                    self.analysis_complete.emit({
                        'success': True,
                        'result': best_result,
                        'all_results': pattern_results,
                        'source': 'pattern'
                    })
                    return
            
            if self._running and self._is_ai_configured():
                context = getattr(self, '_analysis_context', 'default')
                ai_result = self._ai_analyze_streaming(text, context)
                if ai_result:
                    pattern_results.insert(0, ai_result)
            
            if pattern_results:
                best_result = max(pattern_results, key=lambda x: x['confidence'])
                self.analysis_complete.emit({
                    'success': True,
                    'result': best_result,
                    'all_results': pattern_results,
                    'source': 'pattern'
                })
            else:
                self.analysis_error.emit("无法识别密文类型")
                
        except Exception as e:
            self.analysis_error.emit(f"分析失败: {str(e)}")

    def _is_ai_configured(self) -> bool:
        provider = self.config.get('provider', 'openai')
        return provider == 'ollama' or bool(self.config.get('api_key'))
    
    def _ai_analyze_streaming(self, text: str, context: str = 'default') -> Optional[Dict]:
        """
        使用AI流式分析密文，实时输出分析过程
        
        参数:
            text: 待分析文本
            context: 分析上下文 ('default', 'rsa', 'ecc', 'classical')
        """
        if not self._is_ai_configured():
            return None

        prompt = self.get_context_prompt(text, context)

        messages = [
            {'role': 'system', 'content': '你是一个密码学专家，专门分析CTF中的加密问题。请详细展示你的分析思路。'},
            {'role': 'user', 'content': prompt}
        ]

        full_content = ""
        for chunk in self.client.complete_messages(messages, stream=True, temperature=0.3, max_tokens=1000):
            if not self._running:
                break
            if self._is_error_chunk(chunk):
                return None
            full_content += chunk
            self.analysis_chunk.emit(chunk)

        if full_content:
            return self._parse_ai_response(full_content)

        return None

    def _ai_analyze(self, text: str) -> Optional[Dict]:
        """使用AI分析密文（非流式，作为备用）"""
        if not self._is_ai_configured():
            return None

        prompt = self.ANALYSIS_PROMPT.format(ciphertext=text[:500])

        messages = [
            {'role': 'system', 'content': '你是一个密码学专家，专门分析CTF中的加密问题。'},
            {'role': 'user', 'content': prompt}
        ]

        content = ''.join(self.client.complete_messages(messages, stream=False, temperature=0.3, max_tokens=500))
        if content and not self._is_error_chunk(content):
            return self._parse_ai_response(content)

        return None

    @staticmethod
    def _is_error_chunk(chunk: str) -> bool:
        return chunk.startswith(("错误", "API错误", "网络错误", "无法连接", "请求失败"))
    
    def _parse_ai_response(self, content: str) -> Optional[Dict]:
        """解析AI返回的JSON"""
        try:
            # 首先尝试从代码块中提取JSON
            code_block_match = re.search(r'```json\s*([\s\S]*?)\s*```', content)
            if code_block_match:
                json_str = code_block_match.group(1)
                result = json.loads(json_str)
            else:
                # 尝试直接匹配JSON对象
                json_match = re.search(r'\{[\s\S]*\}', content)
                if json_match:
                    result = json.loads(json_match.group())
                else:
                    return None

            return {
                'type': result.get('detected_type', 'Unknown'),
                'algorithm': result.get('algorithm', ''),
                'category': result.get('category', 'classical'),
                'confidence': float(result.get('confidence', 0.5)),
                'description': result.get('description', ''),
                'possible_algorithms': result.get('possible_algorithms', []),
                'suggested_params': result.get('suggested_params', {})
            }
        except Exception as e:
            print(f"解析AI响应失败: {e}")

        return None


class AutoDecryptor:
    """自动解密执行器"""
    
    @staticmethod
    def try_decrypt(text: str, algorithm: str, modules: Dict, params: Dict = None) -> Tuple[bool, str]:
        """尝试使用指定算法解密"""
        if params is None:
            params = {}
        
        module = modules.get(algorithm)
        if not module:
            for name, mod in modules.items():
                if algorithm.lower() in name.lower() or name.lower() in algorithm.lower():
                    module = mod
                    algorithm = name
                    break
        
        if not module:
            return False, f"未找到算法模块: {algorithm}"
        
        try:
            if hasattr(module, 'decrypt_with_params'):
                result = module.decrypt_with_params(text, **params)
            elif hasattr(module, 'decrypt'):
                result = module.decrypt(text, **params)
            else:
                return False, f"模块 {algorithm} 没有解密函数"
            
            if result and not result.startswith("错误") and not result.startswith("解码错误"):
                return True, result
            return False, result
            
        except Exception as e:
            return False, f"解密失败: {str(e)}"
    
    @staticmethod
    def try_all_decryptions(text: str, modules: Dict, algorithms: List[str]) -> List[Tuple[str, bool, str]]:
        """尝试多个算法解密"""
        results = []
        
        for algo in algorithms:
            success, result = AutoDecryptor.try_decrypt(text, algo, modules)
            results.append((algo, success, result))
        
        return results
