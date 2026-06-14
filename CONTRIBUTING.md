# Contributing

Cryptoden welcomes issues, fixes, documentation improvements, and new algorithm modules.

## Development Setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pip install build pytest
```

On Linux/macOS, activate the virtual environment with `source .venv/bin/activate`.

## Validation

Run these checks before opening a pull request:

```bash
python -m pytest
python -m compileall .
python cli.py list
```

For release packaging checks:

```bash
python cleanup.py --apply
python -m build
```

## Adding Algorithms

- Add algorithm modules under `algorithms/` in the appropriate category.
- Prefer simple `encrypt()`, `decrypt()`, or `decrypt_all()` functions.
- Keep parameters explicit so GUI and CLI can infer inputs from function signatures.
- Add or update tests when behavior is non-trivial.

## Security and Responsible Use

Do not submit secrets, private API keys, real challenge credentials, logs with sensitive content, or unauthorized attack workflows. See `SECURITY.md` for vulnerability reporting guidance.
