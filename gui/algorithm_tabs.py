import json
from pathlib import Path


DEFAULT_ALGORITHM_TAB_DEFS = [
    {"name": "RSA", "category": "非对称密码", "desc": "RSA加密/解密及攻击工具", "type": "rsa", "enabled": True},
    {"name": "ECC", "category": "非对称密码", "desc": "椭圆曲线密码工具", "type": "ecc", "enabled": False},
    {"name": "LCG", "category": "非对称密码", "desc": "线性同余生成器攻击工具", "type": "lcg", "enabled": False},
    {"name": "AES", "category": "对称密码", "desc": "AES加密/解密（128/192/256位）", "type": "symmetric", "algorithm": "AES-128", "enabled": True},
    {"name": "DES", "category": "对称密码", "desc": "DES加密/解密", "type": "symmetric", "algorithm": "DES", "enabled": False},
    {"name": "3DES", "category": "对称密码", "desc": "三重DES加密/解密", "type": "symmetric", "algorithm": "3DES", "enabled": False},
    {"name": "Blowfish", "category": "对称密码", "desc": "Blowfish加密/解密", "type": "symmetric", "algorithm": "Blowfish", "enabled": False},
    {"name": "RC4", "category": "对称密码", "desc": "RC4流密码加密/解密", "type": "symmetric", "algorithm": "RC4", "enabled": False},
    {"name": "ChaCha20", "category": "对称密码", "desc": "ChaCha20流密码加密/解密", "type": "symmetric", "algorithm": "ChaCha20", "enabled": False},
    {"name": "Twofish", "category": "对称密码", "desc": "Twofish加密/解密", "type": "symmetric", "algorithm": "Twofish", "enabled": False},
    {"name": "Fernet", "category": "对称密码", "desc": "Fernet对称加密/解密", "type": "symmetric", "algorithm": "Fernet", "enabled": False},
    {"name": "XOR", "category": "对称密码", "desc": "XOR异或加密/解密", "type": "symmetric", "algorithm": "XOR", "enabled": False},
]


def load_algorithm_tab_defs(base_path):
    config_path = Path(base_path) / "algorithm_tabs_config.json"
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
        tabs = data.get("tabs", [])
        if isinstance(tabs, list):
            return tabs
    except Exception:
        pass
    return DEFAULT_ALGORITHM_TAB_DEFS
