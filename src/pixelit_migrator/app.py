"""Pixel IT Profile Migrator — simple profile backup interface."""
from __future__ import annotations

import sys
import time
import threading
from pathlib import Path

from PySide6.QtCore import QObject, QThread, Qt, Signal, Slot, QDir
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QFrame, QHBoxLayout, QLabel,
    QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMessageBox,
    QPushButton, QProgressBar, QVBoxLayout, QWidget, QAbstractItemView,
    QDialog, QDialogButtonBox,
)

from .backup_engine import create_backup, discover_profiles, format_bytes


LIGHT_STYLE = """
QMainWindow, QWidget { background: #f4f7fb; color: #182235; font-family: 'Segoe UI'; font-size: 10pt; }
QFrame#card { background: #ffffff; border: 1px solid #dce4ef; border-radius: 12px; }
QLabel#title { font-size: 22pt; font-weight: 700; color: #13213a; }
QLabel#subtitle { color: #63718a; font-size: 10.5pt; }
QLabel#section { font-size: 12pt; font-weight: 650; color: #1d2d48; }
QLineEdit, QComboBox, QListWidget { background-color: #ffffff; color: #182235; border: 1px solid #cbd5e1; border-radius: 7px; }
QLineEdit { padding: 7px 10px; min-height: 22px; }
QComboBox { padding: 6px 34px 6px 10px; min-height: 26px; }
QComboBox::drop-down { subcontrol-origin: padding; subcontrol-position: top right; width: 28px; border-left: 1px solid #cbd5e1; background: #eef3f9; border-top-right-radius: 6px; border-bottom-right-radius: 6px; }
QComboBox::down-arrow { width: 9px; height: 9px; }
QComboBox QAbstractItemView { background-color: #ffffff; color: #182235; selection-background-color: #1769e0; selection-color: #ffffff; border: 1px solid #cbd5e1; outline: 0; padding: 4px; }
QListWidget { padding: 4px; }
QListWidget::item { min-height: 28px; padding: 5px 8px; }
QLabel { background: transparent; }
QPushButton { background: #e9eef6; color: #182235; border: 1px solid #d4deeb; border-radius: 7px; padding: 9px 14px; font-weight: 600; }
QPushButton:hover { background: #dfe8f5; }
QPushButton#primary { background: #1769e0; color: white; border: 0; padding: 12px 18px; font-size: 11pt; }
QPushButton#primary:hover { background: #1058c3; }
QProgressBar { border: 0; background: #e1e8f2; color: #182235; border-radius: 6px; height: 14px; text-align: center; }
QProgressBar::chunk { background: #1769e0; border-radius: 6px; }
"""
DARK_STYLE = """
QMainWindow, QWidget { background: #111827; color: #e5eaf2; font-family: 'Segoe UI'; font-size: 10pt; }
QFrame#card { background: #1b2638; border: 1px solid #334155; border-radius: 12px; }
QLabel#title { font-size: 22pt; font-weight: 700; color: #f8fafc; }
QLabel#subtitle { color: #a7b4c8; font-size: 10.5pt; }
QLabel#section { font-size: 12pt; font-weight: 650; color: #e5edf8; }
QLineEdit, QComboBox, QListWidget { background-color: #111c2e; color: #e5eaf2; border: 1px solid #475569; border-radius: 7px; }
QLineEdit { padding: 7px 10px; min-height: 22px; }
QComboBox { padding: 6px 34px 6px 10px; min-height: 26px; }
QComboBox::drop-down { subcontrol-origin: padding; subcontrol-position: top right; width: 28px; border-left: 1px solid #475569; background: #29364a; border-top-right-radius: 6px; border-bottom-right-radius: 6px; }
QComboBox::down-arrow { width: 9px; height: 9px; }
QComboBox QAbstractItemView { background-color: #111c2e; color: #e5eaf2; selection-background-color: #1769e0; selection-color: #ffffff; border: 1px solid #475569; outline: 0; padding: 4px; }
QListWidget { padding: 4px; }
QListWidget::item { min-height: 28px; padding: 5px 8px; }
QLabel { background: transparent; }
QPushButton { background: #29364a; color: #e5eaf2; border: 1px solid #475569; border-radius: 7px; padding: 9px 14px; font-weight: 600; }
QPushButton:hover { background: #35465e; }
QPushButton#primary { background: #1769e0; color: white; border: 0; padding: 12px 18px; font-size: 11pt; }
QPushButton#primary:hover { background: #1058c3; }
QProgressBar { border: 0; background: #334155; color: #f8fafc; border-radius: 6px; height: 14px; text-align: center; }
QProgressBar::chunk { background: #38bdf8; border-radius: 6px; }
"""


class _BackupWorker(QObject):
    progress = Signal(int, int, str)
    succeeded = Signal(object)
    failed = Signal(str)
    finished = Signal()

    def __init__(self, profiles: list[Path], extras: list[Path], destination: Path, output_format: str, cancel_event: threading.Event):
        super().__init__()
        self.profiles = profiles
        self.extras = extras
        self.destination = destination
        self.output_format = output_format
        self.cancel_event = cancel_event

    @Slot()
    def run(self):
        try:
            self.progress.emit(0, 0, "Scanning selected data and estimating backup size…")
            result = create_backup(
                self.profiles, self.extras, self.destination, self.output_format,
                progress=self.progress.emit, cancel_event=self.cancel_event,
            )
            self.succeeded.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            self.finished.emit()


class MigratorWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self._active_thread = None
        self._active_worker = None
        self._started_at = 0.0
        self._last_progress = 0
        self._profile_paths: list[Path] = []
        self._custom_profile_folders: dict[str, list[Path]] = {}
        self._cancel_event = threading.Event()
        self.setWindowTitle("Pixel IT Profile Migrator")
        self.resize(1120, 900)
        self.setMinimumSize(900, 760)
        from PySide6.QtCore import QSettings
        self.settings = QSettings("Pixel IT", "Profile Migrator")
        self.theme = self.settings.value("theme", "light")
        self.setStyleSheet(DARK_STYLE if self.theme == "dark" else LIGHT_STYLE)
        self._build_ui()
        self._load_drives()

    def _card(self, layout, title: str):
        frame = QFrame()
        frame.setObjectName("card")
        inner = QVBoxLayout(frame)
        inner.setContentsMargins(18, 16, 18, 18)
        inner.setSpacing(10)
        label = QLabel(title)
        label.setObjectName("section")
        inner.addWidget(label)
        layout.addWidget(frame)
        return inner

    def _build_ui(self):
        root = QWidget()
        page = QVBoxLayout(root)
        page.setContentsMargins(26, 22, 26, 22)
        page.setSpacing(14)

        heading = QVBoxLayout()
        title = QLabel("Profile Backup")
        title.setObjectName("title")
        subtitle = QLabel("Select Windows profiles, add any extra folders, then create a standard folder or ZIP backup.")
        subtitle.setObjectName("subtitle")
        subtitle.setWordWrap(True)
        title_row = QHBoxLayout()
        title_row.addWidget(title, 1)
        self.theme_button = QPushButton()
        self.theme_button.setToolTip("Switch between light and dark appearance")
        self.theme_button.clicked.connect(self._toggle_theme)
        title_row.addWidget(self.theme_button)
        heading.addLayout(title_row)
        heading.addWidget(subtitle)
        page.addLayout(heading)
        self._update_theme_button()

        source_card = self._card(page, "1  ·  Select user profiles")
        drive_row = QHBoxLayout()
        drive_row.addWidget(QLabel("Search drive"))
        self.drive = QComboBox()
        self.drive.currentTextChanged.connect(self._refresh_profiles)
        drive_row.addWidget(self.drive, 1)
        refresh = QPushButton("Rescan")
        refresh.clicked.connect(self._refresh_profiles)
        drive_row.addWidget(refresh)
        source_card.addLayout(drive_row)
        self.profile_list = QListWidget()
        self.profile_list.setMinimumHeight(150)
        self.profile_list.setMaximumHeight(220)
        self.profile_list.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        source_card.addWidget(self.profile_list)
        profile_actions = QHBoxLayout()
        select_all = QPushButton("Select all profiles")
        select_all.clicked.connect(lambda: self._check_profiles(True))
        select_none = QPushButton("Clear selection")
        select_none.clicked.connect(lambda: self._check_profiles(False))
        profile_actions.addWidget(select_all)
        profile_actions.addWidget(select_none)
        profile_actions.addStretch(1)
        source_card.addLayout(profile_actions)
        self.choose_folders_button = QPushButton("Choose folders inside selected profile…")
        self.choose_folders_button.setToolTip("Select specific top-level folders instead of backing up the whole profile.")
        self.choose_folders_button.clicked.connect(self._choose_profile_folders)
        source_card.addWidget(self.choose_folders_button)

        extra_card = self._card(page, "2  ·  Add other files or folders (optional)")
        extra_hint = QLabel("Include files outside the selected profiles, such as business data folders or PST files.")
        extra_hint.setObjectName("subtitle")
        extra_hint.setWordWrap(True)
        extra_card.addWidget(extra_hint)
        self.extra_list = QListWidget()
        self.extra_list.setMinimumHeight(58)
        self.extra_list.setMaximumHeight(110)
        extra_card.addWidget(self.extra_list)
        extra_actions = QHBoxLayout()
        add_folder = QPushButton("＋ Add folder")
        add_folder.clicked.connect(self._add_folder)
        add_file = QPushButton("＋ Add files")
        add_file.clicked.connect(self._add_files)
        remove_extra = QPushButton("Remove selected")
        remove_extra.clicked.connect(self._remove_extra)
        extra_actions.addWidget(add_folder)
        extra_actions.addWidget(add_file)
        extra_actions.addWidget(remove_extra)
        extra_actions.addStretch(1)
        extra_card.addLayout(extra_actions)

        destination_card = self._card(page, "3  ·  Choose backup destination")
        format_row = QHBoxLayout()
        format_row.addWidget(QLabel("Backup type"))
        self.format = QComboBox()
        self.format.addItem("Uncompressed ZIP (single file)", "zip")
        self.format.addItem("Regular folder tree", "folder")
        self.format.currentIndexChanged.connect(self._update_destination_hint)
        format_row.addWidget(self.format, 1)
        destination_card.addLayout(format_row)
        dest_row = QHBoxLayout()
        self.destination = QLineEdit()
        self.destination.setPlaceholderText("Choose where the backup will be saved")
        dest_row.addWidget(self.destination, 1)
        self.browse_destination = QPushButton("Browse…")
        self.browse_destination.clicked.connect(self._choose_destination)
        dest_row.addWidget(self.browse_destination)
        destination_card.addLayout(dest_row)
        self.destination_hint = QLabel("ZIP files are stored without compression and can be opened by standard archive utilities.")
        self.destination_hint.setObjectName("subtitle")
        self.destination_hint.setWordWrap(True)
        destination_card.addWidget(self.destination_hint)

        progress_card = self._card(page, "Backup progress")
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        progress_card.addWidget(self.progress_bar)
        stats = QHBoxLayout()
        self.progress_label = QLabel("Ready when you are.")
        self.progress_label.setWordWrap(True)
        self.eta_label = QLabel("Estimated time remaining: —")
        self.eta_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        stats.addWidget(self.progress_label, 1)
        stats.addWidget(self.eta_label)
        progress_card.addLayout(stats)
        self.current_file = QLabel("")
        self.current_file.setObjectName("subtitle")
        self.current_file.setWordWrap(True)
        progress_card.addWidget(self.current_file)

        footer = QHBoxLayout()
        self.status_label = QLabel("No backup running")
        self.status_label.setObjectName("subtitle")
        footer.addWidget(self.status_label, 1)
        self.start_button = QPushButton("Start backup")
        self.start_button.setObjectName("primary")
        self.start_button.clicked.connect(self._start_backup)
        footer.addWidget(self.start_button)
        self.cancel_button = QPushButton("Cancel backup")
        self.cancel_button.setToolTip("Stop the backup and discard incomplete output.")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self._cancel_backup)
        footer.addWidget(self.cancel_button)
        page.addLayout(footer)
        self.setCentralWidget(root)
        self.statusBar().showMessage("Pixel IT Profile Migrator · Standard, uncompressed backups")

    def _update_theme_button(self):
        self.theme_button.setText("☾  Dark mode" if self.theme == "light" else "☀  Light mode")

    def _toggle_theme(self):
        self.theme = "dark" if self.theme == "light" else "light"
        self.settings.setValue("theme", self.theme)
        self.setStyleSheet(DARK_STYLE if self.theme == "dark" else LIGHT_STYLE)
        self._update_theme_button()

    def _load_drives(self):
        current = ""
        for drive in QDir.drives():
            path = drive.absoluteFilePath()
            if path:
                self.drive.addItem(path, path)
                if path.upper().startswith("C:"):
                    current = path
        if current:
            self.drive.setCurrentText(current)
        elif self.drive.count():
            self.drive.setCurrentIndex(0)
        self._refresh_profiles()

    def _refresh_profiles(self, *_):
        value = self.drive.currentData() or self.drive.currentText()
        if not value:
            return
        root = Path(value)
        self.profile_list.clear()
        try:
            profiles = discover_profiles(root)
        except OSError as exc:
            self.statusBar().showMessage(f"Could not scan {root}: {exc}")
            profiles = []
        self._profile_paths = profiles
        if not profiles:
            item = QListWidgetItem("No profiles found in this drive's Users folder.")
            item.setFlags(Qt.ItemFlag.NoItemFlags)
            self.profile_list.addItem(item)
            return
        for path in profiles:
            item = QListWidgetItem(f"{path.name}    ·    {path}")
            item.setData(Qt.ItemDataRole.UserRole, str(path))
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Unchecked)
            self.profile_list.addItem(item)
        self.statusBar().showMessage(f"Found {len(profiles)} profile(s) in {root}")

    def _check_profiles(self, checked: bool):
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        for index in range(self.profile_list.count()):
            item = self.profile_list.item(index)
            if item.flags() & Qt.ItemFlag.ItemIsUserCheckable:
                item.setCheckState(state)

    def _selected_profiles(self) -> list[Path]:
        selected = []
        for index in range(self.profile_list.count()):
            item = self.profile_list.item(index)
            if item.flags() & Qt.ItemFlag.ItemIsUserCheckable and item.checkState() == Qt.CheckState.Checked:
                profile = Path(item.data(Qt.ItemDataRole.UserRole))
                selected.extend(self._custom_profile_folders.get(str(profile), [profile]))
        return selected

    def _selected_profile_roots(self) -> list[Path]:
        roots = []
        for index in range(self.profile_list.count()):
            item = self.profile_list.item(index)
            if item.flags() & Qt.ItemFlag.ItemIsUserCheckable and item.checkState() == Qt.CheckState.Checked:
                roots.append(Path(item.data(Qt.ItemDataRole.UserRole)))
        return roots

    def _choose_profile_folders(self):
        roots = self._selected_profile_roots()
        if len(roots) != 1:
            QMessageBox.information(self, "Select one profile", "Tick exactly one profile, then choose its folders.")
            return
        profile = roots[0]
        dialog = QDialog(self)
        dialog.setWindowTitle("Choose folders — " + profile.name)
        dialog.resize(520, 560)
        layout = QVBoxLayout(dialog)
        intro = QLabel("Tick the folders to include. Leave everything unticked to back up the whole profile.")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        folders = QListWidget()
        folders.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        layout.addWidget(folders, 1)
        try:
            children = sorted((p for p in profile.iterdir() if p.is_dir() and not p.is_symlink()), key=lambda p: p.name.casefold())
        except OSError as exc:
            QMessageBox.warning(self, "Cannot list folders", "Windows denied access to the profile folder list. " + str(exc))
            return
        custom = self._custom_profile_folders.get(str(profile), [])
        for child in children:
            item = QListWidgetItem("Folder  ·  " + child.name)
            item.setData(Qt.ItemDataRole.UserRole, str(child))
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked if child in custom else Qt.CheckState.Unchecked)
            folders.addItem(item)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            checked = [Path(folders.item(i).data(Qt.ItemDataRole.UserRole)) for i in range(folders.count()) if folders.item(i).checkState() == Qt.CheckState.Checked]
            if checked:
                self._custom_profile_folders[str(profile)] = checked
            else:
                self._custom_profile_folders.pop(str(profile), None)
            self.status_label.setText("Folder scope updated for " + profile.name if checked else "Whole profile selected")

    def _cancel_backup(self):
        if self._active_thread is not None:
            self._cancel_event.set()
            self.cancel_button.setEnabled(False)
            self.status_label.setText("Cancelling backup…")
            self.progress_label.setText("Cancellation requested; finishing current file chunk…")

    def _add_folder(self):
        value = QFileDialog.getExistingDirectory(self, "Select an additional folder")
        if value:
            self._add_extra_path(Path(value))

    def _add_files(self):
        values, _ = QFileDialog.getOpenFileNames(self, "Select additional files")
        for value in values:
            self._add_extra_path(Path(value))

    def _add_extra_path(self, path: Path):
        resolved = path.resolve()
        for index in range(self.extra_list.count()):
            if Path(self.extra_list.item(index).data(Qt.ItemDataRole.UserRole)) == resolved:
                return
        item = QListWidgetItem(str(resolved))
        item.setData(Qt.ItemDataRole.UserRole, str(resolved))
        self.extra_list.addItem(item)

    def _remove_extra(self):
        for item in self.extra_list.selectedItems():
            self.extra_list.takeItem(self.extra_list.row(item))

    def _update_destination_hint(self, *_):
        if self.format.currentData() == "zip":
            self.destination.setPlaceholderText("Choose the ZIP file path, e.g. E:/Backups/Computer-Profile.zip")
            self.destination_hint.setText("A standard ZIP file stored without compression. Open it with Windows Explorer, 7-Zip or other ZIP utilities.")
        else:
            self.destination.setPlaceholderText("Choose the parent folder for the backup")
            self.destination_hint.setText("Creates a timestamped PixelIT-Backup folder containing regular files and folders. No proprietary format.")

    def _choose_destination(self):
        if self.format.currentData() == "zip":
            value, _ = QFileDialog.getSaveFileName(self, "Save standard ZIP backup", "PixelIT-Backup.zip", "ZIP archive (*.zip)")
        else:
            value = QFileDialog.getExistingDirectory(self, "Choose backup destination folder")
        if value:
            self.destination.setText(value)

    def _start_backup(self):
        if self._active_thread is not None:
            return
        profiles = self._selected_profiles()
        extras = [Path(self.extra_list.item(i).data(Qt.ItemDataRole.UserRole)) for i in range(self.extra_list.count())]
        destination_text = self.destination.text().strip()
        if not profiles and not extras:
            QMessageBox.warning(self, "Choose data", "Select at least one user profile or add a file/folder.")
            return
        if not destination_text:
            QMessageBox.warning(self, "Choose destination", "Select where the backup should be saved.")
            return
        destination = Path(destination_text)
        if self.format.currentData() == "folder" and destination.exists() and not destination.is_dir():
            QMessageBox.warning(self, "Invalid destination", "For folder backups, choose an existing parent folder.")
            return
        if self.format.currentData() == "zip" and destination.exists() and destination.is_dir():
            QMessageBox.warning(self, "Invalid destination", "For ZIP backups, choose a filename ending in .zip.")
            return
        self._started_at = time.monotonic()
        self._cancel_event = threading.Event()
        self._last_progress = 0
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_label.setText("Scanning files and estimating total size…")
        self.eta_label.setText("Estimated time remaining: calculating…")
        self.current_file.clear()
        self.start_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.status_label.setText("Backup running")
        self._active_thread = QThread(self)
        self._active_worker = _BackupWorker(profiles, extras, destination, self.format.currentData(), self._cancel_event)
        self._active_worker.moveToThread(self._active_thread)
        self._active_thread.started.connect(self._active_worker.run)
        self._active_worker.progress.connect(self._update_progress)
        self._active_worker.succeeded.connect(self._backup_succeeded)
        self._active_worker.failed.connect(self._backup_failed)
        self._active_worker.finished.connect(self._active_thread.quit)
        self._active_worker.finished.connect(self._active_worker.deleteLater)
        self._active_thread.finished.connect(self._worker_finished)
        self._active_thread.finished.connect(self._active_thread.deleteLater)
        self._active_thread.start()

    @Slot(int, int, str)
    def _update_progress(self, completed: int, total: int, current: str):
        if total <= 0:
            self.progress_bar.setRange(0, 0)
            self.progress_label.setText(current)
            self.eta_label.setText("Estimated time remaining: calculating…")
            return
        if self.progress_bar.maximum() == 0:
            self.progress_bar.setRange(0, 100)
        percent = min(100, int(completed * 100 / total))
        self.progress_bar.setValue(percent)
        elapsed = max(0.01, time.monotonic() - self._started_at)
        rate = completed / elapsed if completed else 0
        remaining = max(0, total - completed)
        eta = self._format_duration(remaining / rate) if rate > 0 else "calculating…"
        self.progress_label.setText(f"{percent}%  ·  {format_bytes(completed)} of {format_bytes(total)}")
        self.eta_label.setText(f"Estimated time remaining: {eta}")
        self.current_file.setText(f"Current file: {current}")

    @staticmethod
    def _format_duration(seconds: float) -> str:
        seconds = max(0, int(seconds))
        if seconds < 60:
            return f"{seconds}s"
        minutes, seconds = divmod(seconds, 60)
        if minutes < 60:
            return f"{minutes}m {seconds}s"
        hours, minutes = divmod(minutes, 60)
        return f"{hours}h {minutes}m"

    @Slot(object)
    def _backup_succeeded(self, result: dict):
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        elapsed = self._format_duration(time.monotonic() - self._started_at)
        self.progress_label.setText(f"Completed · {format_bytes(result['bytes'])} · {result['files']:,} files")
        self.eta_label.setText(f"Time taken: {elapsed}")
        self.current_file.setText(f"Saved to: {result['output']}")
        self.status_label.setText("Backup complete")
        QMessageBox.information(
            self, "Backup complete",
            f"Backup completed successfully.\n\nFiles: {result['files']:,}\n"
            f"Readable data: {format_bytes(result['bytes'])}\nTime: {elapsed}\n\n"
            f"Location:\n{result['output']}"
        )

    @Slot(str)
    def _backup_failed(self, message: str):
        if "cancelled by the operator" in message.casefold():
            self.status_label.setText("Backup cancelled")
            self.progress_label.setText("Backup cancelled; incomplete output was discarded.")
            self.eta_label.setText("Estimated time remaining: —")
            self.current_file.setText("No completed backup was created.")
            return
        self.status_label.setText("Backup failed")
        self.progress_label.setText("Backup stopped before completion.")
        self.eta_label.setText("Estimated time remaining: —")
        self.current_file.setText(message)
        QMessageBox.critical(self, "Backup failed", f"The backup could not be completed.\n\n{message}")

    @Slot()
    def _worker_finished(self):
        self.start_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self._active_thread = None
        self._active_worker = None

    def closeEvent(self, event):
        if self._active_thread is not None:
            QMessageBox.warning(self, "Backup in progress", "Wait for the backup to finish before closing the application.")
            event.ignore()
        else:
            event.accept()


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Pixel IT Profile Migrator")
    app.setFont(QFont("Segoe UI", 10))
    window = MigratorWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
