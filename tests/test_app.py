import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QProgressBar, QPushButton

from pixelit_migrator.app import MigratorWindow

# Keep QApplication alive for the entire test module to avoid Qt teardown races.
_APP = QApplication.instance() or QApplication([])


def test_main_window_shows_backup_workflow_without_package_preview():
    window = MigratorWindow()
    assert isinstance(window.start_button, QPushButton)
    assert window.start_button.text() == "Start backup"
    assert isinstance(window.progress_bar, QProgressBar)
    assert window.format.count() == 2
    assert window.format.itemData(0) == "zip"
    assert window.format.itemData(1) == "folder"
    assert not hasattr(window, "passphrase")
    assert not hasattr(window, "restore_manifest")
    assert window.theme in {"light", "dark"}
    original_theme = window.theme
    window.theme_button.click()
    assert window.theme != original_theme
    window.theme_button.click()
    assert window.theme == original_theme
    window.close()
    window.deleteLater()
    _APP.sendPostedEvents()
    _APP.processEvents()
