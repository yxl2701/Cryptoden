"""
简单替换密码加密模块
====================

【算法介绍】
简单替换密码（Simple Substitution Cipher）是最基本的替换密码之一，
每个明文字母被映射到另一个唯一的密文字母，形成一对一的替换关系。

与凯撒密码不同，替换密码的映射关系是任意的（不局限于固定偏移），
因此有 26! 种可能的密钥。

【加密原理】
1. 构建一个26字母的映射表（明文→密文）
2. 将明文中的每个字母根据映射表替换

【解密原理】
1. 构建逆映射表（密文→明文）
2. 将密文中的每个字母根据逆映射表替换

【示例】
密钥（映射表）: QWERTYUIOPASDFGHJKLZXCVBNM
  明文 A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
  密文 Q W E R T Y U I O P A S D F G H J K L Z X C V B N M

明文: HELLO
密文: ITSSG

【参数说明】
- mapping: 替换映射表，26个字母的排列（大写），默认为逆序映射 ZYXWVUTSRQPONMLKJIHGFEDCBA
"""

import random
import re


def _validate_mapping(mapping: str) -> str:
    """验证并标准化映射表"""
    if len(mapping) != 26:
        raise ValueError("映射表必须是26个字母")
    mapping = mapping.upper()
    if len(set(mapping)) != 26:
        raise ValueError("映射表不能有重复字母")
    return mapping


def _build_enc_map(mapping: str) -> dict:
    """构建加密映射表（A→X）"""
    return {chr(ord('A') + i): mapping[i] for i in range(26)}


def _build_dec_map(mapping: str) -> dict:
    """构建解密映射表（X→A）"""
    return {mapping[i]: chr(ord('A') + i) for i in range(26)}


def _apply_map(text: str, char_map: dict) -> str:
    """应用映射表"""
    result = []
    for char in text:
        if char.isalpha():
            upper_char = char.upper()
            if upper_char in char_map:
                mapped = char_map[upper_char]
                if char.islower():
                    result.append(mapped.lower())
                else:
                    result.append(mapped)
            else:
                result.append(char)
        else:
            result.append(char)
    return ''.join(result)


def encrypt(plaintext, mapping="ZYXWVUTSRQPONMLKJIHGFEDCBA"):
    """
    简单替换密码加密

    根据映射表将明文字母替换为密文字母。

    参数:
        plaintext (str): 明文
        mapping (str): 26个字母的排列，表示A→X的映射

    返回:
        str: 密文

    示例:
        >>> encrypt("HELLO", "ZYXWVUTSRQPONMLKJIHGFEDCBA")
        'SVOOL'
        >>> encrypt("hello", "ZYXWVUTSRQPONMLKJIHGFEDCBA")
        'svool'
    """
    try:
        mapping = _validate_mapping(mapping)
        enc_map = _build_enc_map(mapping)
        return _apply_map(plaintext, enc_map)
    except ValueError as e:
        return f"错误: {str(e)}"


def decrypt(ciphertext, mapping="ZYXWVUTSRQPONMLKJIHGFEDCBA"):
    """
    简单替换密码解密

    根据映射表将密文字母还原为明文字母。

    参数:
        ciphertext (str): 密文
        mapping (str): 26个字母的排列，表示A→X的映射

    返回:
        str: 明文

    示例:
        >>> decrypt("SVOOL", "ZYXWVUTSRQPONMLKJIHGFEDCBA")
        'HELLO'
    """
    try:
        mapping = _validate_mapping(mapping)
        dec_map = _build_dec_map(mapping)
        return _apply_map(ciphertext, dec_map)
    except ValueError as e:
        return f"错误: {str(e)}"


def decrypt_all(ciphertext):
    """
    简单替换密码频率分析破解

    使用英文字母频率分析自动破解简单替换密码。
    返回最可能的解密结果。

    参数:
        ciphertext (str): 密文

    返回:
        str: 自动破解后的最可能明文
    """
    # 英文字母频率（从高到低）
    english_freq = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'

    # 统计密文字母频率
    letters_only = ''.join(c.upper() for c in ciphertext if c.isalpha())
    if not letters_only:
        return "错误: 密文中没有字母"

    freq = {}
    for c in letters_only:
        freq[c] = freq.get(c, 0) + 1

    # 按频率排序
    sorted_chars = sorted(freq.keys(), key=lambda c: (-freq[c], c))

    # 构建映射：高频密文字母 → 高频英文字母
    mapping_list = [''] * 26
    for i, c in enumerate(sorted_chars):
        if i < len(english_freq):
            mapping_list[ord(c) - ord('A')] = english_freq[i]

    # 剩余未出现的字母按原序映射
    remaining_plain = [c for c in english_freq if c not in mapping_list]
    remaining_cipher = [chr(ord('A') + i) for i in range(26) if mapping_list[i] == '']
    for i, c in enumerate(remaining_cipher):
        if i < len(remaining_plain):
            mapping_list[ord(c) - ord('A')] = remaining_plain[i]

    # 构建解密映射表（密文→明文）
    dec_map = {}
    for i, c in enumerate(mapping_list):
        if c:
            dec_map[chr(ord('A') + i)] = c

    # 应用映射
    return _apply_map(ciphertext, dec_map)