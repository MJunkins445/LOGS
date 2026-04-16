import os

import pytest
from PyQt5.QtWidgets import QApplication


# Keep Qt headless for CI/local terminal test runs.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    yield app

