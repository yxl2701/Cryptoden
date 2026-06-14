"""Safely remove generated project artifacts.

Default mode is dry-run. Use --apply to delete matched files and directories.
Rules are read from cleanup_config.json and intentionally target only generated
artifacts such as build output, caches, logs, and local records.
"""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Iterable


BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = BASE_DIR / "cleanup_config.json"


def _load_config() -> dict:
    return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _safe_target(path: Path) -> bool:
    resolved = path.resolve()
    return resolved != BASE_DIR and _is_relative_to(resolved, BASE_DIR)


def _is_protected(path: Path, protected_paths: Iterable[str]) -> bool:
    resolved = path.resolve()
    for protected in protected_paths:
        protected_path = (BASE_DIR / protected).resolve()
        if resolved == protected_path:
            return True
    return False


def _path_size(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    total = 0
    for child in path.rglob("*"):
        if child.is_file():
            total += child.stat().st_size
    return total


def _format_size(size: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024


def _collect_targets(config: dict) -> list[Path]:
    targets: set[Path] = set()
    protected_paths = config.get("protected_paths", [])

    for dirname in config.get("directories", []):
        for match in BASE_DIR.rglob(dirname):
            if match.is_dir() and _safe_target(match) and not _is_protected(match, protected_paths):
                targets.add(match)

    for pattern in config.get("file_patterns", []):
        for match in BASE_DIR.rglob(pattern):
            if match.is_file() and _safe_target(match) and not _is_protected(match, protected_paths):
                targets.add(match)

    for filename in config.get("files", []):
        match = BASE_DIR / filename
        if match.exists() and _safe_target(match) and not _is_protected(match, protected_paths):
            targets.add(match)

    collapsed = []
    for target in sorted(targets, key=lambda p: (len(p.parts), str(p).lower())):
        if any(_is_relative_to(target, parent) for parent in collapsed):
            continue
        collapsed.append(target)

    return sorted(collapsed, key=lambda p: (len(p.parts), str(p).lower()), reverse=True)


def _delete_target(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description="Preview or remove generated project artifacts.")
    parser.add_argument("--apply", action="store_true", help="Actually delete matched cleanup targets.")
    args = parser.parse_args()

    config = _load_config()
    targets = _collect_targets(config)

    mode = "DELETE" if args.apply else "DRY-RUN"
    total_size = sum(_path_size(target) for target in targets)
    print(f"[{mode}] {len(targets)} cleanup targets, {_format_size(total_size)} total")

    for target in targets:
        rel = target.relative_to(BASE_DIR)
        kind = "dir " if target.is_dir() else "file"
        print(f"[{kind}] {rel} ({_format_size(_path_size(target))})")
        if args.apply:
            _delete_target(target)

    if not args.apply:
        print("\nNo files were deleted. Run `python cleanup.py --apply` to delete these targets.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
