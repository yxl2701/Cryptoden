"""Feature detection helpers for recursive decrypt."""

import json
import math
import re
import base64
from typing import List

from utils.recursive_config import load_recursive_config


CUSTOM_FEATURE_DEFAULT_SCORE = 25


def normalize_custom_features(raw_features):
    """Normalize user-defined feature rules from config.json."""
    if isinstance(raw_features, dict):
        raw_features = raw_features.get("custom_features", [])
    result = []
    if not isinstance(raw_features, list):
        return result
    for item in raw_features:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        pattern = str(item.get("pattern", "")).strip()
        if not name or not pattern:
            continue
        try:
            score = int(item.get("score", CUSTOM_FEATURE_DEFAULT_SCORE))
        except Exception:
            score = CUSTOM_FEATURE_DEFAULT_SCORE
        result.append({
            "name": name,
            "pattern": pattern,
            "score": score,
            "ignore_case": bool(item.get("ignore_case", True)),
            "strong": bool(item.get("strong", True)),
        })
    return result


def load_custom_features(base_path=None):
    config = load_recursive_config(base_path)
    return normalize_custom_features(config.get("custom_features", []))


def disabled_builtin_features(feature_config=None):
    if isinstance(feature_config, dict):
        raw = feature_config.get("disabled_builtin_features", [])
    else:
        raw = []
    if not isinstance(raw, list):
        return set()
    return {str(item).strip() for item in raw if str(item).strip()}


def _append_builtin(features, disabled, name):
    if name not in disabled:
        features.append(name)


def _looks_decodable_base64(text: str) -> bool:
    compact = ''.join(text.split())
    try:
        decoded = base64.b64decode(compact + ('=' * ((-len(compact)) % 4)), validate=True)
        decoded_text = decoded.decode('utf-8')
    except Exception:
        return False
    if not decoded_text:
        return False
    printable = sum(1 for c in decoded_text if c.isprintable() or c in '\r\n\t')
    return printable / max(len(decoded_text), 1) > 0.92


def _looks_decodable_base32(text: str) -> bool:
    compact = ''.join(text.split()).upper()
    try:
        decoded = base64.b32decode(compact + ('=' * ((-len(compact)) % 8)), casefold=True)
        decoded_text = decoded.decode('utf-8')
    except Exception:
        return False
    if not decoded_text:
        return False
    printable = sum(1 for c in decoded_text if c.isprintable() or c in '\r\n\t')
    return printable / max(len(decoded_text), 1) > 0.92


def detect_result_features(text: str, custom_features=None) -> List[str]:
    """识别解密结果的常见明文或下一步解码特征。"""
    if not text:
        return []

    stripped = text.strip()
    lower = stripped.lower()
    features = []
    disabled = disabled_builtin_features(custom_features)

    if re.search(r'(?i)(flag|ctf)\s*\{[^\r\n{}]{1,200}\}', stripped):
        _append_builtin(features, disabled, "flag格式")
    elif re.search(r'(?i)[a-z0-9_]{2,32}\s*\{[^\r\n{}]{1,200}\}', stripped):
        _append_builtin(features, disabled, "花括号文本")
    if re.search(r'(?i)\b(flag|ctf|key|secret|password|token)\b', stripped):
        _append_builtin(features, disabled, "关键词")
    if re.search(r'https?://[^\s]+', stripped):
        _append_builtin(features, disabled, "URL")
    if re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', stripped):
        _append_builtin(features, disabled, "JWT")
    if stripped.startswith('{') and stripped.endswith('}') or stripped.startswith('[') and stripped.endswith(']'):
        try:
            json.loads(stripped)
            _append_builtin(features, disabled, "JSON")
        except Exception:
            pass
    if re.search(r'<[A-Za-z][^>]*>.*</[A-Za-z][^>]*>', stripped, re.S):
        _append_builtin(features, disabled, "XML/HTML")
    if '-----BEGIN ' in stripped and '-----END ' in stripped:
        _append_builtin(features, disabled, "PEM")
    if re.fullmatch(r'[0-9a-fA-F]{8,}', stripped) and len(stripped) % 2 == 0:
        _append_builtin(features, disabled, "Hex候选")
    if (
        re.fullmatch(r'[A-Z2-7]{12,}={0,6}', stripped, re.IGNORECASE)
        and len(stripped.rstrip('=')) % 8 != 1
        and _looks_decodable_base32(stripped)
    ):
        _append_builtin(features, disabled, "Base32候选")
    if (
        re.fullmatch(r'[A-Za-z0-9+/]{4,}={0,2}', stripped)
        and len(stripped.rstrip('=')) % 4 != 1
        and (any(c.islower() for c in stripped) or any(ch in stripped for ch in '+/='))
        and _looks_decodable_base64(stripped)
    ):
        _append_builtin(features, disabled, "Base64候选")
    if re.fullmatch(r'[1-9A-HJ-NP-Za-km-z]{12,}', stripped):
        _append_builtin(features, disabled, "Base58候选")
    if re.fullmatch(r'[.\-/\s]{4,}', stripped) and any(ch in stripped for ch in '.-'):
        _append_builtin(features, disabled, "Morse候选")
    if stripped.isalpha() and 6 <= len(stripped) <= 64:
        _append_builtin(features, disabled, "ROT候选")
    elif re.fullmatch(r"[A-Za-z\s.,!?'-]{6,128}", stripped) and any(c.isalpha() for c in stripped):
        _append_builtin(features, disabled, "ROT候选")
    elif re.fullmatch(r'[A-Za-z0-9+/=]{8,4096}', stripped) and any(c.isdigit() for c in stripped):
        _append_builtin(features, disabled, "ROT候选")
    elif re.fullmatch(r'[A-Za-z0-9?;:<>=/]{8,4096}', stripped) and any(c.isdigit() for c in stripped):
        _append_builtin(features, disabled, "ROT候选")
    elif '%' in stripped and re.search(r'%[A-Za-z0-9]{2}', stripped):
        _append_builtin(features, disabled, "ROT候选")
    if len(stripped) >= 8 and all(33 <= ord(c) <= 126 for c in stripped):
        punct = sum(1 for c in stripped if not c.isalnum())
        if punct / max(len(stripped), 1) >= 0.18:
            _append_builtin(features, disabled, "ROT47候选")
        elif ' ' not in stripped and not ('{' in stripped and '}' in stripped) and punct >= 3 and any(ch in stripped for ch in '#`~!}'):
            _append_builtin(features, disabled, "ROT47候选")
    if stripped.isalnum() and 8 <= len(stripped) <= 128 and any(c.isalpha() for c in stripped) and any(c.isdigit() for c in stripped):
        _append_builtin(features, disabled, "字母数字候选")
    if '%' in stripped and re.search(r'%[0-9a-fA-F]{2}', stripped):
        _append_builtin(features, disabled, "URL编码候选")

    printable = sum(1 for c in stripped if c.isprintable())
    printable_ratio = printable / max(len(stripped), 1)
    letters = sum(1 for c in stripped if c.isalpha())
    common_words = re.findall(r'\b(the|and|you|that|have|for|not|with|this|hello|admin|root)\b', lower)
    if len(stripped) >= 8 and printable_ratio > 0.92 and letters / max(len(stripped), 1) > 0.45:
        if stripped.count(' ') or common_words or any(ch in stripped for ch in '{}_-'):
            _append_builtin(features, disabled, "高可读文本")
    if common_words:
        _append_builtin(features, disabled, "英文词汇")

    chars = set(stripped)
    if len(stripped) >= 16 and chars:
        entropy = 0.0
        for ch in chars:
            p = stripped.count(ch) / len(stripped)
            entropy -= p * math.log2(p)
        if entropy < 3.8 and printable_ratio > 0.9:
            _append_builtin(features, disabled, "低熵可读")

    for item in normalize_custom_features(custom_features):
        flags = re.IGNORECASE if item.get("ignore_case", True) else 0
        try:
            if re.search(item["pattern"], stripped, flags):
                features.append(item["name"])
        except re.error:
            continue

    result = []
    for feature in features:
        if feature not in result:
            result.append(feature)
    return result


def is_feature_match(features: List[str], custom_features=None) -> bool:
    strong = {"flag格式", "URL", "JWT", "JSON", "XML/HTML", "PEM", "Base58候选", "Morse候选", "ROT候选", "ROT47候选", "字母数字候选"}
    strong.update(item["name"] for item in normalize_custom_features(custom_features) if item.get("strong", True))
    return any(feature in strong for feature in features)


def feature_score(features: List[str], custom_features=None) -> int:
    weights = {
        "flag格式": 100,
        "花括号文本": 90,
        "Base64候选": 80,
        "Base32候选": 80,
        "Base58候选": 80,
        "Morse候选": 75,
        "ROT候选": 35,
        "ROT47候选": 35,
        "字母数字候选": 18,
        "Hex候选": 80,
        "关键词": 30,
        "JSON": 30,
        "URL": 30,
        "JWT": 30,
        "PEM": 30,
        "高可读文本": 20,
        "英文词汇": 20,
        "URL编码候选": 10,
        "低熵可读": 5,
    }
    weights.update({item["name"]: item.get("score", CUSTOM_FEATURE_DEFAULT_SCORE) for item in normalize_custom_features(custom_features)})
    return sum(weights.get(feature, 0) for feature in features or [])


def is_repeatable_recursive_algo(algo_name: str) -> bool:
    lower = algo_name.lower()
    return any(name in lower for name in ('base', 'hex', 'url', 'unicode', 'html'))


def is_allowed_by_text_features(text: str, algo_name: str) -> bool:
    features = detect_result_features(text)
    lower = algo_name.lower()
    if "Hex候选" in features:
        return 'hex' in lower
    if "Base32候选" in features:
        return 'base32' in lower or 'base64' in lower
    if "Base64候选" in features:
        return 'base64' in lower
    if "URL编码候选" in features:
        return 'url' in lower
    return True
