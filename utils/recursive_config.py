"""Shared recursive decrypt settings."""

import json
from pathlib import Path


DEFAULT_RECURSIVE_CONFIG = {
    "max_depth": 5,
    "max_workers": 4,
    "max_tasks": 1000,
    "max_results_per_depth": 50,
    "max_total_attempts": 20000,
    "max_display_results": 100,
    "brute_force_small_keyspaces": True,
    "custom_features": [],
    "disabled_builtin_features": [],
}


def load_recursive_config(base_path=None):
    config = dict(DEFAULT_RECURSIVE_CONFIG)
    root = Path(base_path) if base_path else Path(__file__).parent.parent
    config_path = root / "config.json"
    try:
        if config_path.exists():
            data = json.loads(config_path.read_text(encoding="utf-8"))
            saved = data.get("recursive_decrypt", {})
            if isinstance(saved, dict):
                for key in config:
                    if key in saved:
                        config[key] = saved[key]
    except Exception:
        pass
    return config
