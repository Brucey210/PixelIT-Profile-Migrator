import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QTabWidget

from pixelit_migrator.app import MigratorWindow


def test_main_window_constructs_three_workflow_tabs():
    app = QApplication.instance() or QApplication([])
    window = MigratorWindow()
    tabs = window.centralWidget()
    assert isinstance(tabs, QTabWidget)
    assert tabs.count() == 3
    assert [tabs.tabText(i) for i in range(tabs.count())] == [
        "Create migration package",
        "Restore package",
        "Outlook & credentials",
    ]
    assert "Alpha" in window.windowTitle()
    window.close()
    app.processEvents()
