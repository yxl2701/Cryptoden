"""
递归解密模块
============
实现多层嵌套密码的递归解密，自动尝试所有解密算法链。
适用于 CTF 中多层编码/加密的场景。

用法:
    from de_recursion import recursive_decrypt
    result = recursive_decrypt("U0VGQ1RGe3Rlc3R9")
    print(format_recursive_result(result))
"""

import re
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple
from core.crypto_loader import CryptoLoader
from utils.recursive_config import load_recursive_config
from utils.recursive_features import detect_result_features, normalize_custom_features

# 默认匹配模式（不区分大小写）
DEFAULT_PATTERNS = ['flag{', 'ctf{', 'flag', 'ctf', 'key', 'password', 'secret']

# 找到匹配后继续探索的额外深度
EXTRA_DEPTH_AFTER_MATCH = 2

# 编码类算法（多层编码中常见）
ENCODING_ALGOS = {'base64', 'base32', 'hex', 'url', 'unicode', 'html', 'rot13'}
STRICT_ENCODING_FEATURES = {"Hex候选", "Base32候选", "Base58候选", "Base64候选", "URL编码候选"}
STRONG_RECURSIVE_FEATURES = STRICT_ENCODING_FEATURES | {
    "flag格式", "花括号文本", "JSON", "XML/HTML", "PEM", "JWT", "关键词", "URL",
    "Morse候选", "ROT候选", "ROT47候选", "字母数字候选",
}

_ENCODING_TOKENS = (
    'base', 'hex', 'url', 'unicode', 'html', 'rot', 'morse', '摩斯',
    'brainfuck', 'quoted', '与佛', '社会主义核心价值观',
)
_LAST_RESORT_TOKENS = ('aes', 'des', 'blowfish', 'chacha', 'fernet', 'rc4', 'twofish', 'xor', 'rsa', 'ecc')
_SYMMETRIC_TOKENS = ('aes', 'des', 'blowfish', 'chacha', 'fernet', 'rc4', 'twofish', 'xor')


def _is_encoding_algo(algo_name: str) -> bool:
    lower = algo_name.lower()
    return any(token in lower for token in _ENCODING_TOKENS)


def _is_symmetric_algo(algo_name: str) -> bool:
    lower = algo_name.lower()
    return any(token in lower for token in _SYMMETRIC_TOKENS)


def _categorize_algo(algo_name: str) -> str:
    """Return 'encoding', 'symmetric', or 'other'."""
    if _is_encoding_algo(algo_name):
        return 'encoding'
    if _is_symmetric_algo(algo_name):
        return 'symmetric'
    return 'other'


def _is_related_encoding(algo_name: str, features: List[str]) -> bool:
    """Check if algo is a closely related encoding for the detected features."""
    lower = algo_name.lower()
    if "Base64候选" in features:
        return 'base32' in lower
    if "Base32候选" in features:
        return 'base64' in lower
    if "Base58候选" in features:
        return 'base58' in lower
    if "Hex候选" in features:
        return 'base' in lower
    if "URL编码候选" in features:
        return 'url' in lower or 'base' in lower
    return False

def _is_repeatable_algo(algo_name: str) -> bool:
    lower = algo_name.lower()
    return any(name in lower for name in ('base', 'hex', 'url', 'unicode', 'html', 'rot'))


def _is_last_resort(algo_lower: str) -> bool:
    return any(t in algo_lower for t in _LAST_RESORT_TOKENS)


def _allowed_by_detected_features(features: List[str], algo_name: str) -> bool:
    lower = algo_name.lower()
    if "Hex候选" in features:
        return 'hex' in lower
    if "Base32候选" in features:
        return 'base32' in lower or 'base64' in lower
    if "Base58候选" in features:
        return 'base58' in lower
    if "Base64候选" in features:
        return 'base64' in lower
    if "URL编码候选" in features:
        return 'url' in lower
    return True


def _strip_trailing_non_printable(text: str) -> str:
    """Remove trailing non-printable characters that interfere with feature regex."""
    i = len(text)
    while i > 0:
        c = text[i - 1]
        if c.isprintable() or c in '\n\r\t':
            break
        i -= 1
    return text[:i]


def _algo_lower_matches(algo_lower: str, tokens: Tuple[str, ...]) -> bool:
    for token in tokens:
        if token.startswith('='):
            if algo_lower == token[1:]:
                return True
            continue
        if token in algo_lower:
            return True
    return False


def _ciphertext_algo_hints(text: str, features: List[str]) -> Tuple[List[Tuple[str, ...]], bool]:
    """Return preferred algorithm name tokens and whether they are high confidence."""
    stripped = text.strip()
    compact = ''.join(stripped.split())
    hints: List[Tuple[str, ...]] = []
    strict = False
    has_strict_encoding_feature = any(feature in STRICT_ENCODING_FEATURES for feature in features)

    if "Hex候选" in features:
        hints.append(('=hex',))
        strict = True
    if "Base32候选" in features:
        hints.append(('=base32',))
        strict = True
    if "Base58候选" in features:
        hints.append(('=base58',))
        strict = True
    if "Base64候选" in features:
        hints.append(('=base64',))
        strict = True
    if "URL编码候选" in features:
        hints.append(('=url',))
        strict = True
    if "Morse候选" in features:
        hints.append(('morse', '摩斯'))
        strict = True
    if "ROT候选" in features and "ROT47候选" not in features and (
        not has_strict_encoding_feature
        or "Base64候选" in features
    ):
        hints.append(('caesar', 'rot13', 'rot18'))
    if "ROT候选" in features and "URL编码候选" in features and "ROT47候选" in features:
        hints.append(('caesar', 'rot13', 'rot18'))
    if "ROT47候选" in features:
        hints.append(('rot47',))
        if len(text) <= 64 and (any(c.isalpha() for c in text) or any(c.isdigit() for c in text)):
            hints.append(('rot13', 'rot18'))
        strict = True

    if re.search(r'&(?:#[0-9]+|#x[0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]+);', stripped):
        hints.append(('html',))
        strict = True
    if re.search(r'\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|U\+[0-9a-fA-F]{4,6}', stripped):
        hints.append(('unicode',))
        strict = True
    if re.search(r'=[0-9a-fA-F]{2}', stripped):
        hints.append(('quoted-printable', 'quoted'))
        strict = True
    if compact and re.fullmatch(r'[.\-/]+', compact) and any(ch in compact for ch in '.-'):
        hints.append(('morse', '摩斯'))
        strict = True
    if compact and re.fullmatch(r'[><+\-.,\[\]]+', compact) and any(ch in compact for ch in '[]<>'):
        hints.append(('brainfuck',))
        strict = True
    if stripped and all(ch in '富强民主文明和谐自由平等公正法治爱国敬业诚信友善' for ch in stripped):
        hints.append(('社会主义核心价值观',))
        strict = True
    if re.search(r'[佛曰如是我闻]', stripped):
        hints.append(('与佛论禅',))
        strict = True

    return hints, strict


def _rank_algorithms_for_text(
    algo_index: List[Tuple[str, str]],
    text: str,
    features: List[str],
) -> Tuple[List[str], List[str], List[str], List[str]]:
    """Split algorithms into feature-matched first pass, encoding fallback, and full fallback."""
    hints, strict = _ciphertext_algo_hints(text, features)
    has_builtin_encoding_filter = any(feature in STRICT_ENCODING_FEATURES for feature in features)
    preferred: List[str] = []
    encoding_fallback: List[str] = []
    full_fallback: List[str] = []
    last_resort: List[str] = []
    seen_preferred = set()

    for tokens in hints:
        for algo_name, algo_lower in algo_index:
            if algo_name in seen_preferred:
                continue
            if _algo_lower_matches(algo_lower, tokens):
                preferred.append(algo_name)
                seen_preferred.add(algo_name)

    has_exact_preferred = bool(preferred)

    for algo_name, algo_lower in algo_index:
        if algo_name in seen_preferred:
            continue
        if hints and any(_algo_lower_matches(algo_lower, tokens) for tokens in hints):
            preferred.append(algo_name)
        elif strict and has_builtin_encoding_filter and not has_exact_preferred and _allowed_by_detected_features(features, algo_name):
            preferred.append(algo_name)
        elif strict and has_builtin_encoding_filter and _is_related_encoding(algo_name, features):
            encoding_fallback.append(algo_name)
        elif strict and has_builtin_encoding_filter:
            full_fallback.append(algo_name)
        elif _is_last_resort(algo_lower):
            last_resort.append(algo_name)
        else:
            full_fallback.append(algo_name)
    return preferred, encoding_fallback, full_fallback, last_resort


def parse_patterns(pattern_arg: Optional[List[str]] = None) -> List[str]:
    """解析模式参数，支持空格和逗号分隔"""
    if not pattern_arg:
        return list(DEFAULT_PATTERNS)
    result = []
    for item in pattern_arg:
        # 逗号分隔
        for part in item.split(','):
            part = part.strip()
            if not part:
                continue
            # 空格分隔
            for sub in part.split():
                sub = sub.strip()
                if sub:
                    result.append(sub)
    return result if result else list(DEFAULT_PATTERNS)


def _is_error_output(text: str) -> bool:
    """判断输出是否为错误信息"""
    if not text:
        return True
    stripped = text.strip()
    if not stripped:
        return True
    error_starts = ('错误:', '解码失败', '解码错误', '失败:')
    return any(stripped.startswith(s) for s in error_starts)


def _is_likely_plaintext_for_keyword(text: str) -> bool:
    if not text:
        return False
    stripped = text.strip()
    printable = sum(1 for c in stripped if c.isprintable()) / max(len(stripped), 1)
    noisy = sum(1 for c in stripped if not (c.isalnum() or c.isspace() or c in '{}_:-.@/')) / max(len(stripped), 1)
    return printable > 0.92 and noisy < 0.18


def _score_result(
    text: str,
    original: str,
    algo_name: str = "",
    custom_features=None,
    detected_features: Optional[List[str]] = None,
) -> float:
    """给解密结果打分，越高越可能是目标明文"""
    score = 0.0
    # 编码类算法优先（多层编码常见）
    algo_lower = algo_name.lower()
    if algo_lower in ENCODING_ALGOS or any(name in algo_lower for name in ('base', 'hex', 'url', 'unicode', 'html')):
        score += 20
    # 太短的结果（1-2字符）不太可能是有效明文
    if len(text) <= 2:
        score -= 30
    # 更短通常更好（解码后变短）
    if len(text) < len(original):
        ratio = len(text) / max(len(original), 1)
        score += 10 * (1 - ratio)
    # 长度不变但内容变了也可能是有效解码
    elif len(text) == len(original) and text != original:
        score += 3
    # 可打印字符比例高
    printable = sum(1 for c in text if 32 <= ord(c) <= 126)
    score += printable / max(len(text), 1) * 5
    # 包含常见英文字母
    letters = sum(1 for c in text.lower() if 'a' <= c <= 'z')
    score += letters / max(len(text), 1) * 3
    # 包含常见单词分隔符（空格、下划线、连字符、大括号）
    separators = sum(1 for c in text if c in ' _{}-')
    score += separators / max(len(text), 1) * 5
    features = detected_features if detected_features is not None else detect_result_features(text, custom_features)
    feature_scores = {
        "flag格式": 100,
        "花括号文本": 90,
        "关键词": 30,
        "JSON": 30,
        "URL": 30,
        "JWT": 30,
        "PEM": 30,
        "Base32候选": 80,
        "Base64候选": 80,
        "Hex候选": 80,
        "URL编码候选": 15,
        "高可读文本": 12,
        "英文词汇": 80,
    }
    score += sum(feature_scores.get(feature, 0) for feature in features)
    custom_scores = {
        item["name"]: item.get("score", 25)
        for item in normalize_custom_features(custom_features)
    }
    score += sum(custom_scores.get(feature, 0) for feature in features)
    return score


def _match_priority(item: Dict) -> int:
    text = item.get("text", "")
    matched = [str(p).lower() for p in item.get("matched_patterns", [])]
    if re.search(r'(?i)(flag|ctf)\s*\{[^\r\n{}]{1,200}\}', text):
        return 1000
    if any(p in ('flag{', 'ctf{') for p in matched):
        return 900
    if any(p in ('flag', 'ctf') for p in matched):
        return 400
    if any(p in ('key', 'password', 'secret') for p in matched):
        return 300
    if not item.get("is_feature_only"):
        return 500
    return 100


def _best_match_key(item: Dict) -> Tuple[int, int, int, int]:
    priority = _match_priority(item)
    chain_len = len(item.get("chain", []))
    depth = int(item.get("depth", 0))
    text_len = len(item.get("text", ""))
    has_params = int(any(step.get("params") for step in item.get("chain", [])))
    if priority >= 900:
        return (priority, depth, -chain_len, has_params, text_len)
    return (priority, has_params, -chain_len, -depth, -text_len)


def recursive_decrypt(
    ciphertext: str,
    base_path: Optional[Path] = None,
    max_depth: Optional[int] = None,
    patterns: Optional[List[str]] = None,
    case_sensitive: bool = False,
    match_all: bool = False,
    max_results_per_depth: Optional[int] = None,
    max_total_attempts: Optional[int] = None,
    brute_force_small_keyspaces: Optional[bool] = None,
) -> Dict:
    """
    递归解密入口

    参数:
        ciphertext: 初始密文
        base_path: 项目根路径（默认自动检测）
        max_depth: 最大递归深度
        patterns: 匹配模式列表
        case_sensitive: 是否区分大小写匹配
        match_all: True=所有模式都要匹配, False=任一匹配即可

    返回:
        {
            "matched": [...],
            "best": {...} or None,     # 最佳匹配（深度最深 + 路径最短）
            "all_chains": [...],
            "total_attempts": N,
            "max_depth_reached": N,
            "patterns_used": [...]
        }
    """
    if base_path is None:
        base_path = Path(__file__).parent.resolve()
    config = load_recursive_config(base_path)
    max_depth = int(config["max_depth"] if max_depth is None else max_depth)
    max_results_per_depth = int(config["max_results_per_depth"] if max_results_per_depth is None else max_results_per_depth)
    max_total_attempts = int(config["max_total_attempts"] if max_total_attempts is None else max_total_attempts)
    if brute_force_small_keyspaces is None:
        brute_force_small_keyspaces = bool(config["brute_force_small_keyspaces"])
    feature_config = {
        "custom_features": config.get("custom_features", []),
        "disabled_builtin_features": config.get("disabled_builtin_features", []),
    }
    if patterns is None:
        patterns = list(DEFAULT_PATTERNS)

    loader = CryptoLoader(base_path)
    loader.load_all_modules()

    visited: Dict[str, int] = {}
    matched_results: List[Dict] = []
    all_results: List[Dict] = []
    total_attempts = 0
    algo_names = loader.get_all_algo_names('decrypt')
    algo_index = [(name, name.lower()) for name in algo_names]
    repeatable_algos = {name for name in algo_names if _is_repeatable_algo(name)}
    feature_cache: Dict[str, Tuple[str, List[str]]] = {}
    decrypt_cache: Dict[Tuple[str, str], List[Tuple[str, str, bool]]] = {}

    def _features_for(text: str) -> Tuple[str, List[str]]:
        """Return printable text plus cached recursive features for that text."""
        printable_text = _strip_trailing_non_printable(text)
        cached = feature_cache.get(printable_text)
        if cached is not None:
            return cached
        features = detect_result_features(printable_text, feature_config)
        cached = (printable_text, features)
        feature_cache[printable_text] = cached
        return cached

    def _matches(text: str) -> List[str]:
        """检查文本是否匹配模式"""
        found = []
        for i, p in enumerate(patterns):
            pattern_text = p if case_sensitive else p.lower()
            search_text = text if case_sensitive else text.lower()
            if pattern_text == 'flag':
                if pattern_text not in search_text:
                    continue
                if len(text) > 128 and not any(ch in text for ch in ' {}[]()<>\n\t'):
                    continue
                if not _is_likely_plaintext_for_keyword(text):
                    continue
                found.append(p)
            elif pattern_text in ('ctf', 'key', 'password', 'secret'):
                flags = 0 if case_sensitive else re.IGNORECASE
                if not re.search(rf'(?<![a-z0-9]){re.escape(p)}(?![a-z0-9])', text, flags):
                    continue
                if pattern_text in ('ctf', 'key') and not _is_likely_plaintext_for_keyword(text):
                    continue
                found.append(p)
            elif pattern_text in search_text:
                found.append(p)

        if match_all:
            return found if len(found) == len(patterns) else []
        return found

    def _chain_summary(chain: List[Dict]) -> str:
        """将解密链转为简洁描述"""
        if not chain:
            return "原始输入"
        parts = []
        for s in chain:
            label = s['algorithm']
            if s.get('params'):
                label += f"({s['params']})"
            parts.append(label)
        return " → ".join(parts)

    def _iter_decrypt_candidates(algo_name: str, text: str) -> List[Tuple[str, str, bool]]:
        """Return default decrypt result and small-keyspace brute-force results."""
        cache_key = (algo_name, text)
        cached = decrypt_cache.get(cache_key)
        if cached is not None:
            return cached

        candidates: List[Tuple[str, str, bool]] = []
        seen = set()
        try:
            result = loader.execute_decrypt(algo_name, text)
            if result is not None:
                result = str(result)
                if not _is_error_output(result):
                    seen.add(result)
                    candidates.append((result, "", False))
        except Exception:
            pass
        # 不再做任何补全/对齐：仅凭密文特征驱动算法选择与加速

        if not brute_force_small_keyspaces:
            decrypt_cache[cache_key] = candidates
            return candidates

        info = loader.get_module_info(algo_name, 'decrypt')
        module = info.get('module') if info else None
        decrypt_all = getattr(module, 'decrypt_all', None)
        if not callable(decrypt_all):
            decrypt_cache[cache_key] = candidates
            return candidates
        try:
            output = str(decrypt_all(text))
        except Exception:
            decrypt_cache[cache_key] = candidates
            return candidates
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            params = "爆破"
            candidate = line
            match = re.match(r'^(偏移量|shift)\s*([0-9]+)\s*[:：]\s*(.*)$', line, re.IGNORECASE)
            if match:
                params = f"shift={match.group(2)}"
                candidate = match.group(3)
            elif ':' in line or '：' in line:
                sep = ':' if ':' in line else '：'
                params, candidate = [part.strip() for part in line.split(sep, 1)]
            key = (params, candidate)
            if candidate and key not in seen:
                seen.add(key)
                candidates.append((candidate, params, True))
        decrypt_cache[cache_key] = candidates
        return candidates

    def _recurse(text: str, chain: List[Dict], depth: int, found_match: bool = False):
        """递归解密"""
        nonlocal total_attempts

        if any(_match_priority(item) >= 1000 for item in matched_results):
            return
        prev_depth = visited.get(text)
        if prev_depth is not None and prev_depth <= depth:
            return
        visited[text] = depth
        matched = _matches(text)
        printable_text, features = _features_for(text)
        has_pattern_match = bool(matched)
        if has_pattern_match:
            matched_results.append({
                "text": text,
                "matched_patterns": matched,
                "chain": list(chain),
                "chain_summary": _chain_summary(chain),
                "depth": depth,
                "features": features,
                "is_feature_only": False,
            })
            # 强格式匹配后才限制额外探索；普通关键词可能仍是编码中间层。
            priority = _match_priority(matched_results[-1])
            found_match = priority >= 900
            if priority >= 1000:
                return

        if depth == max_depth:
            return

        # 无强编码特征且未匹配模式 → 剪枝（弱特征如「高可读」「低熵」不继续深入）
        if not has_pattern_match and not any(f in STRONG_RECURSIVE_FEATURES for f in features):
            return
        if found_match and depth >= EXTRA_DEPTH_AFTER_MATCH:
            return

        candidates = []
        preferred_algos, encoding_fallback_algos, full_fallback_algos, last_resort_algos = _rank_algorithms_for_text(algo_index, printable_text, features)

        def _collect_candidates(candidate_algos: List[str]) -> None:
            nonlocal total_attempts
            for algo_name in candidate_algos:
                if algo_name not in repeatable_algos:
                    if any(step.get("algorithm") == algo_name for step in chain):
                        continue
                if total_attempts >= max_total_attempts:
                    break
                for result, params, is_brute in _iter_decrypt_candidates(algo_name, text):
                    total_attempts += 1
                    if total_attempts > max_total_attempts:
                        break

                    if result is None or _is_error_output(result):
                        continue
                    if result == text:
                        continue

                    step = {"algorithm": algo_name, "depth": depth, "params": params, "is_brute": is_brute}
                    new_chain = chain + [step]
                    _, result_features = _features_for(result)

                    candidates.append({
                        "text": result,
                        "chain": new_chain,
                        "score": _score_result(result, text, algo_name, feature_config, result_features) + (1 if is_brute and params else 0),
                    })

        # 优先 → 编码兜底 → 全量回退，每层只取最高优先级的有效候选
        _collect_candidates(preferred_algos)
        strict_encode = any(feature in STRICT_ENCODING_FEATURES for feature in features)
        if not candidates and encoding_fallback_algos and total_attempts < max_total_attempts:
            limit = encoding_fallback_algos[:5] if strict_encode else encoding_fallback_algos
            _collect_candidates(limit)
        allow_full_fallback = not strict_encode and "ROT47候选" not in features
        if not candidates and full_fallback_algos and total_attempts < max_total_attempts:
            if allow_full_fallback:
                _collect_candidates(full_fallback_algos)
            elif strict_encode:
                _collect_candidates(full_fallback_algos[:5])

        # 按分数排序，只保留前 N 个继续递归
        candidates.sort(key=lambda x: x["score"], reverse=True)
        top = candidates[:max_results_per_depth]

        for c in top:
            all_results.append({
                "text": c["text"],
                "chain": c["chain"],
                "chain_summary": _chain_summary(c["chain"]),
                "depth": depth + 1,
                "score": c["score"],
            })
            _recurse(c["text"], c["chain"], depth + 1, found_match)

    _recurse(ciphertext, [], 0)

    # 按深度排序（深度越深越靠前），同深度按文本排序
    matched_results.sort(key=lambda x: (-x["depth"], x["text"]))
    all_results.sort(key=lambda x: (x["depth"], x["text"]))

    # 选最佳匹配：深度最深 + 路径最短
    best = None
    if matched_results:
        best = max(matched_results, key=_best_match_key)
    best_candidate = None
    if all_results:
        best_candidate = max(
            all_results,
            key=lambda item: (item.get("score", 0), item.get("depth", 0), -len(item.get("text", ""))),
        )

    return {
        "matched": matched_results,
        "best": best,
        "best_candidate": best_candidate,
        "all_chains": all_results,
        "total_attempts": total_attempts,
        "max_depth_reached": max([r["depth"] for r in all_results] + [0]),
        "patterns_used": list(patterns),
        "input": ciphertext,
        "settings": {
            "max_depth": max_depth,
            "max_results_per_depth": max_results_per_depth,
            "max_total_attempts": max_total_attempts,
            "brute_force_small_keyspaces": brute_force_small_keyspaces,
        },
    }


def format_recursive_result(
    result: Dict,
    show_all: bool = False,
    brief: bool = False,
) -> str:
    """格式化递归解密结果为可读文本"""
    lines = []

    # ── 摘要 ──
    matched_count = len(result["matched"])
    total = result["total_attempts"]
    max_d = result["max_depth_reached"]

    if brief:
        # 紧凑模式
        if result["best"]:
            b = result["best"]
            lines.append(f"✓ 匹配: {b['text']}")
            lines.append(f"  路径: {b['chain_summary']}")
        elif result.get("best_candidate"):
            b = result["best_candidate"]
            lines.append(f"△ 候选: {b['text']}")
            lines.append(f"  路径: {b['chain_summary']}")
            lines.append(f"  未命中匹配模式 (尝试 {total} 次, 最大深度 {max_d})")
        else:
            lines.append(f"✗ 未匹配 (尝试 {total} 次, 最大深度 {max_d})")
        return "\n".join(lines)

    # ── 详细模式 ──
    if result["best"]:
        b = result["best"]
        lines.append("╔══════════════════════════════════════╗")
        lines.append("║          ★ 最佳匹配结果 ★            ║")
        lines.append("╚══════════════════════════════════════╝")
        lines.append("")
        lines.append(f"  明文: {b['text']}")
        lines.append(f"  深度: {b['depth']}")
        lines.append(f"  匹配: {', '.join(b['matched_patterns'])}")
        lines.append(f"  路径: {b['chain_summary']}")
        lines.append("")
    else:
        lines.append("╔══════════════════════════════════════╗")
        lines.append("║        ✗ 未找到匹配结果              ║")
        lines.append("╚══════════════════════════════════════╝")
        lines.append("")
        if result.get("best_candidate"):
            b = result["best_candidate"]
            lines.append("最佳候选:")
            lines.append(f"  明文: {b['text']}")
            lines.append(f"  深度: {b['depth']}")
            lines.append(f"  路径: {b['chain_summary']}")
            lines.append("")

    # ── 全部匹配结果 ──
    if matched_count > 0:
        lines.append(f"📋 全部匹配结果 ({matched_count} 个):\n")
        for i, item in enumerate(result["matched"], 1):
            mark = "★" if item is result["best"] else " "
            chain_str = item["chain_summary"]
            lines.append(f"  {mark} [{i}] depth={item['depth']} | {item['text']}")
            if chain_str:
                lines.append(f"      路径: {chain_str}")
            lines.append("")

    # ── 全部解密链 ──
    if show_all and result["all_chains"]:
        lines.append(f"🔗 全部解密链 ({len(result['all_chains'])} 条):\n")
        for item in result["all_chains"][:25]:
            lines.append(f"  depth={item['depth']} | {item['text'][:80]}")
            lines.append(f"      路径: {item['chain_summary']}")
            lines.append("")
        if len(result["all_chains"]) > 25:
            lines.append(f"  ... (共 {len(result['all_chains'])} 条)")

    # ── 统计 ──
    lines.append("─" * 40)
    lines.append(
        f"尝试: {total} 次 | 最大深度: {max_d} | "
        f"匹配模式: {', '.join(result['patterns_used'][:5])}"
        f"{'...' if len(result['patterns_used']) > 5 else ''}"
    )

    return "\n".join(lines)
