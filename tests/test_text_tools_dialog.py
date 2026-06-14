import subprocess
import sys
from pathlib import Path


def _run_dialog_script(script: str) -> str:
    root = Path(__file__).parent.parent
    command = [sys.executable, "-c", script]
    result = subprocess.run(
        command,
        cwd=str(root),
        capture_output=True,
        text=True,
        env={**__import__("os").environ, "QT_QPA_PLATFORM": "offscreen"},
        timeout=30,
        check=True,
    )
    return result.stdout.strip()


def test_analysis_result_does_not_replace_source_text():
    output = _run_dialog_script(
        "import sys; "
        "from pathlib import Path; "
        "from importlib.util import module_from_spec,spec_from_file_location; "
        "from PyQt5.QtWidgets import QApplication; "
        "app=QApplication.instance() or QApplication(sys.argv); "
        "p=Path('gui')/'text_tools_dialog.py'; "
        "spec=spec_from_file_location('m', p); "
        "m=module_from_spec(spec); spec.loader.exec_module(m); "
        "d=m.TextToolsDialog(text='abcd ef'); d.show_stats(); d.accept(); print(d.result_text())"
    )
    assert output == "abcd ef"


def test_transform_result_can_be_applied():
    output = _run_dialog_script(
        "import sys; "
        "from pathlib import Path; "
        "from importlib.util import module_from_spec,spec_from_file_location; "
        "from PyQt5.QtWidgets import QApplication; "
        "app=QApplication.instance() or QApplication(sys.argv); "
        "p=Path('gui')/'text_tools_dialog.py'; "
        "spec=spec_from_file_location('m', p); "
        "m=module_from_spec(spec); spec.loader.exec_module(m); "
        "d=m.TextToolsDialog(text='abcdef'); d.apply_split(); d.accept(); print(d.result_text())"
    )
    assert output == "abcd ef"
