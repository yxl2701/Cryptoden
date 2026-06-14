from __future__ import annotations

from collections import Counter
import re
from urllib.parse import unquote


def split_text_by_length(text: str, length: int, separator: str = " ") -> str:
    if length <= 0:
        raise ValueError("length must be positive")
    if not text:
        return ""
    return separator.join(text[i:i + length] for i in range(0, len(text), length))


def decode_escaped_text(text: str) -> str:
    return text.encode("utf-8").decode("unicode_escape")


def remove_all_whitespace(text: str) -> str:
    return "".join(text.split())


def remove_spaces_only(text: str) -> str:
    return text.replace(" ", "")


def keep_hex_characters(text: str) -> str:
    return "".join(ch for ch in text if ch in "0123456789abcdefABCDEF")


def keep_alphanumeric(text: str) -> str:
    return "".join(ch for ch in text if ch.isalnum())


def url_decode_text(text: str) -> str:
    return unquote(text)


def reverse_text(text: str) -> str:
    return text[::-1]


def get_text_statistics(text: str) -> dict:
    lines = text.splitlines()
    characters = len(text)
    letters = sum(1 for ch in text if ch.isalpha())
    digits = sum(1 for ch in text if ch.isdigit())
    whitespace = sum(1 for ch in text if ch.isspace())
    hex_chars = len(keep_hex_characters(text))
    compact_text = remove_all_whitespace(text)
    return {
        "characters": characters,
        "lines": len(lines) if text else 0,
        "non_whitespace_characters": len(compact_text),
        "unique_characters": len(set(text)),
        "words": len(re.findall(r"\S+", text)),
        "letters": letters,
        "digits": digits,
        "whitespace": whitespace,
        "hex_characters": hex_chars,
        "is_probably_hex": bool(compact_text) and len(compact_text) == hex_chars and len(compact_text) % 2 == 0,
    }


def get_character_frequencies(text: str, top_n: int = 20) -> list:
    counts = Counter(text)
    return counts.most_common(top_n)
