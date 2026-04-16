"""
L.O.G.S. — Log, Observe, Guard, Secure
Combined firewall analyzer + network scanner entry point.

Prioritizes netwatch_demo's FirewallDemoWindow as the main UI,
with netwatch's port scanning integrated as a tab.

Usage (run as Administrator for full functionality):
    cd C:\\My_Java_Project\\CIS_485\\LOGS
    py main.py

Requirements:
    pip install -r requirements.txt
    nmap binary: https://nmap.org/download.html  (must be on system PATH)
"""

import logging
import os
import sys


def setup_logging() -> logging.Logger:
    """
    Configure logging to both a rotating file and the console.
    Log files are stored in LOGS/logs/logs.log.
    """
    log_dir  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "logs.log")

    fmt = logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(fmt)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(fmt)

    root_logger = logging.getLogger("logs")
    root_logger.setLevel(logging.DEBUG)
    root_logger.propagate = False

    # Ensure setup is idempotent across repeated application starts/imports.
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)
        try:
            handler.close()
        except Exception:
            pass

    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    return root_logger


def main():
    logger = setup_logging()
    logger.info("=" * 60)
    logger.info("L.O.G.S. starting")
    logger.info("=" * 60)

    # Ensure data directory exists for baseline storage
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    os.makedirs(data_dir, exist_ok=True)

    try:
        from PyQt5.QtWidgets import QApplication
        from PyQt5.QtCore    import Qt
    except ImportError:
        print("ERROR: PyQt5 is not installed.  Fix: pip install PyQt5")
        sys.exit(1)

    # High-DPI support
    if hasattr(Qt, "AA_EnableHighDpiScaling"):
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, "AA_UseHighDpiPixmaps"):
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("L.O.G.S.")
    app.setStyle("Fusion")

    # Light palette
    try:
        from PyQt5.QtGui import QColor, QPalette
        pal = QPalette()
        pal.setColor(QPalette.Window,          QColor(238, 241, 246))
        pal.setColor(QPalette.WindowText,      QColor(26,  30,  46))
        pal.setColor(QPalette.Base,            QColor(248, 250, 252))
        pal.setColor(QPalette.AlternateBase,   QColor(221, 227, 237))
        pal.setColor(QPalette.Text,            QColor(26,  30,  46))
        pal.setColor(QPalette.Button,          QColor(221, 227, 237))
        pal.setColor(QPalette.ButtonText,      QColor(26,  30,  46))
        pal.setColor(QPalette.Highlight,       QColor(30,  136, 229))
        pal.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
        app.setPalette(pal)
    except Exception:
        pass

    try:
        from gui.firewall_window import FirewallDemoWindow
    except Exception as exc:
        logger.critical(f"Failed to import FirewallDemoWindow: {exc}", exc_info=True)
        try:
            from PyQt5.QtWidgets import QMessageBox
            msg = QMessageBox()
            msg.setIcon(QMessageBox.Critical)
            msg.setWindowTitle("Startup Error")
            msg.setText(f"L.O.G.S. failed to start:\n\n{exc}")
            msg.exec_()
        except Exception:
            print(f"FATAL: {exc}")
        sys.exit(1)

    window = FirewallDemoWindow()
    window.show()

    logger.info("FirewallDemoWindow displayed — entering event loop")
    exit_code = app.exec_()
    logger.info(f"L.O.G.S. exiting with code {exit_code}")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
