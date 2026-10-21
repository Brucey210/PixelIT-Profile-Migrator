from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QFileDialog, QFormLayout, QHBoxLayout, QLabel,
    QLineEdit, QMainWindow, QMessageBox, QPushButton, QTabWidget, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget, QProgressBar
)

from pixelit_migrator.core import (
    create_encrypted_package, inventory, preview_package, restore_package
)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Pixel IT Profile Migrator")
        self.resize(1040, 700)
        self.source_path: Path | None = None
        self.package_path: Path | None = None
        self.records = []
        tabs = QTabWidget()
        tabs.addTab(self._build_capture_tab(), "Capture")
        tabs.addTab(self._build_restore_tab(), "Restore")
        tabs.addTab(self._build_safety_tab(), "Credential & Outlook")
        self.setCentralWidget(tabs)
        self.statusBar().showMessage("Prototype — verify backups before use")

    def _build_capture_tab(self):
        w = QWidget(); layout = QVBoxLayout(w)
        form = QFormLayout()
        self.source_edit = QLineEdit(); self.source_edit.setReadOnly(True)
        browse = QPushButton("Choose source profile…"); browse.clicked.connect(self.choose_source)
        row = QHBoxLayout(); row.addWidget(self.source_edit); row.addWidget(browse)
        form.addRow("Source folder", row)
        self.pass_edit = QLineEdit(); self.pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Package passphrase", self.pass_edit)
        self.package_edit = QLineEdit(); self.package_edit.setReadOnly(True)
        out = QPushButton("Choose package destination…"); out.clicked.connect(self.choose_package)
        row2 = QHBoxLayout(); row2.addWidget(self.package_edit); row2.addWidget(out)
        form.addRow("Encrypted package", row2)
        layout.addLayout(form)
        self.inventory_table = QTableWidget(0, 3)
        self.inventory_table.setHorizontalHeaderLabels(["Include", "Relative path", "Size (bytes)"])
        self.inventory_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.inventory_table)
        buttons = QHBoxLayout()
        scan = QPushButton("Scan profile"); scan.clicked.connect(self.scan_source)
        all_btn = QPushButton("Select all"); all_btn.clicked.connect(lambda: self.set_all(True))
        none_btn = QPushButton("Select none"); none_btn.clicked.connect(lambda: self.set_all(False))
        create = QPushButton("Create encrypted package"); create.clicked.connect(self.create_package)
        buttons.addWidget(scan); buttons.addWidget(all_btn); buttons.addWidget(none_btn); buttons.addStretch(); buttons.addWidget(create)
        layout.addLayout(buttons)
        self.progress = QProgressBar(); self.progress.setRange(0, 1); self.progress.setValue(0)
        layout.addWidget(self.progress)
        return w

    def _build_restore_tab(self):
        w = QWidget(); layout = QVBoxLayout(w); form = QFormLayout()
        self.restore_package_edit = QLineEdit(); self.restore_package_edit.setReadOnly(True)
        browse = QPushButton("Choose encrypted package…"); browse.clicked.connect(self.choose_restore_package)
        row = QHBoxLayout(); row.addWidget(self.restore_package_edit); row.addWidget(browse)
        form.addRow("Package", row)
        self.restore_dest_edit = QLineEdit(); self.restore_dest_edit.setReadOnly(True)
        dest = QPushButton("Choose destination profile…"); dest.clicked.connect(self.choose_restore_dest)
        row2 = QHBoxLayout(); row2.addWidget(self.restore_dest_edit); row2.addWidget(dest)
        form.addRow("Destination", row2)
        self.restore_pass_edit = QLineEdit(); self.restore_pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Package passphrase", self.restore_pass_edit)
        layout.addLayout(form)
        self.restore_table = QTableWidget(0, 3)
        self.restore_table.setHorizontalHeaderLabels(["Status", "Relative path", "Details"])
        self.restore_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.restore_table)
        buttons = QHBoxLayout()
        preview = QPushButton("Preview restore"); preview.clicked.connect(self.preview_restore)
        restore = QPushButton("Restore selected-safe files"); restore.clicked.connect(self.do_restore)
        buttons.addWidget(preview); buttons.addStretch(); buttons.addWidget(restore)
        layout.addLayout(buttons)
        note = QLabel("Conflicts are skipped by default. Review the preview before restoring. This prototype does not preserve all Windows ACLs, EFS, or alternate data streams.")
        note.setWordWrap(True); layout.addWidget(note)
        return w

    def _build_safety_tab(self):
        w = QWidget(); layout = QVBoxLayout(w)
        layout.addWidget(QLabel("<b>Credentials</b>"))
        layout.addWidget(QLabel("This tool does not extract Windows passwords, Credential Manager secrets, browser passwords, cookies, or authentication tokens. Use supported password-manager exports/sync and sign in again where required."))
        layout.addWidget(QLabel("<b>Outlook</b>"))
        layout.addWidget(QLabel("PST files can be included by scanning the profile or selecting their folder. OST files are normally rebuilt and should not be treated as the only mailbox backup. Signatures, templates, rules, contacts and local calendars require separate inventory and validation."))
        layout.addWidget(QLabel("<b>Before field use</b>"))
        layout.addWidget(QLabel("Keep an independent backup. Verify the report and destination. This prototype is not production-approved."))
        layout.addStretch()
        return w

    def choose_source(self):
        value = QFileDialog.getExistingDirectory(self, "Choose source profile")
        if value: self.source_path = Path(value); self.source_edit.setText(value)

    def choose_package(self):
        value, _ = QFileDialog.getSaveFileName(self, "Save encrypted package", "migration.pitm", "Pixel IT packages (*.pitm)")
        if value: self.package_path = Path(value); self.package_edit.setText(value)

    def scan_source(self):
        if not self.source_path:
            QMessageBox.warning(self, "Source required", "Choose a source folder first."); return
        try:
            self.records = inventory(self.source_path)
            self.inventory_table.setRowCount(len(self.records))
            for i, rec in enumerate(self.records):
                check = QTableWidgetItem()
                check.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
                check.setCheckState(Qt.CheckState.Checked)
                self.inventory_table.setItem(i, 0, check)
                self.inventory_table.setItem(i, 1, QTableWidgetItem(rec.relative_path))
                self.inventory_table.setItem(i, 2, QTableWidgetItem(str(rec.size)))
            self.statusBar().showMessage(f"Scanned {len(self.records)} files")
        except Exception as exc: QMessageBox.critical(self, "Scan failed", str(exc))

    def set_all(self, checked):
        for i in range(self.inventory_table.rowCount()):
            item = self.inventory_table.item(i, 0)
            if item: item.setCheckState(Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked)

    def create_package(self):
        if not self.source_path or not self.package_path:
            QMessageBox.warning(self, "Missing details", "Choose a source and package destination."); return
        passphrase = self.pass_edit.text()
        if len(passphrase) < 12:
            QMessageBox.warning(self, "Passphrase too short", "Use a unique passphrase of at least 12 characters."); return
        selected = [self.inventory_table.item(i, 1).text() for i in range(self.inventory_table.rowCount()) if self.inventory_table.item(i, 0).checkState() == Qt.CheckState.Checked]
        if not selected:
            QMessageBox.warning(self, "Nothing selected", "Select at least one file."); return
        answer = QMessageBox.question(self, "Create package", f"Package {len(selected)} files? The source will not be deleted.")
        if answer != QMessageBox.StandardButton.Yes: return
        try:
            self.progress.setRange(0, 0)
            records = create_encrypted_package(self.source_path, self.package_path, passphrase, selected)
            self.progress.setRange(0, 1); self.progress.setValue(1)
            QMessageBox.information(self, "Package created", f"Encrypted package created. Files: {len(records)}\nKeep the passphrase safe; it cannot be recovered.")
            self.statusBar().showMessage("Package created; verify it before source retirement")
        except Exception as exc: QMessageBox.critical(self, "Package failed", str(exc))
        finally: self.progress.setRange(0, 1); self.progress.setValue(0)

    def choose_restore_package(self):
        value, _ = QFileDialog.getOpenFileName(self, "Choose package", "", "Pixel IT packages (*.pitm)")
        if value: self.restore_package_edit.setText(value)

    def choose_restore_dest(self):
        value = QFileDialog.getExistingDirectory(self, "Choose destination profile")
        if value: self.restore_dest_edit.setText(value)

    def _restore_inputs(self):
        package = Path(self.restore_package_edit.text())
        destination = Path(self.restore_dest_edit.text())
        password = self.restore_pass_edit.text()
        if not package.is_file() or not destination.is_dir() or not password:
            raise ValueError("Choose a valid package, destination folder, and passphrase.")
        return package, destination, password

    def preview_restore(self):
        try:
            package, destination, password = self._restore_inputs()
            items = preview_package(package, password, destination)
            self.restore_table.setRowCount(len(items))
            for i, item in enumerate(items):
                self.restore_table.setItem(i, 0, QTableWidgetItem(item.status))
                self.restore_table.setItem(i, 1, QTableWidgetItem(item.relative_path))
                self.restore_table.setItem(i, 2, QTableWidgetItem(item.reason))
            self.statusBar().showMessage(f"Preview complete: {len(items)} entries")
        except Exception as exc: QMessageBox.critical(self, "Preview failed", str(exc))

    def do_restore(self):
        try:
            package, destination, password = self._restore_inputs()
            if self.restore_table.rowCount() == 0:
                QMessageBox.warning(self, "Preview required", "Run Preview restore first."); return
            answer = QMessageBox.question(self, "Confirm restore", "Restore files that are new or identical-safe? Conflicts will be skipped; source package is retained.")
            if answer != QMessageBox.StandardButton.Yes: return
            items = restore_package(package, password, destination)
            self.restore_table.setRowCount(len(items))
            for i, item in enumerate(items):
                self.restore_table.setItem(i, 0, QTableWidgetItem(item.status))
                self.restore_table.setItem(i, 1, QTableWidgetItem(item.relative_path))
                self.restore_table.setItem(i, 2, QTableWidgetItem(item.reason))
            QMessageBox.information(self, "Restore finished", f"Processed {len(items)} entries. Review all statuses before closing the job.")
        except Exception as exc: QMessageBox.critical(self, "Restore failed", str(exc))


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
