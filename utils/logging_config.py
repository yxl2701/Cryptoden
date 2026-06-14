"""Application logging and crash handling."""

import logging
import sys
import traceback
from pathlib import Path


LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_FILE = LOG_DIR / "cryptoden.log"


def setup_logging():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        filename=str(LOG_FILE),
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        encoding="utf-8",
    )
    logging.getLogger("cryptoden").info("Cryptoden started")


def install_excepthook(show_dialog=False):
    def handle_exception(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return

        setup_logging()
        logging.getLogger("cryptoden").error(
            "Unhandled exception",
            exc_info=(exc_type, exc_value, exc_traceback),
        )

        if show_dialog:
            try:
                from PyQt5.QtWidgets import QMessageBox

                QMessageBox.critical(
                    None,
                    "程序错误",
                    f"程序发生未处理错误，日志已写入:\n{LOG_FILE}\n\n{exc_value}",
                )
            except Exception:
                pass

        traceback.print_exception(exc_type, exc_value, exc_traceback)

    sys.excepthook = handle_exception
