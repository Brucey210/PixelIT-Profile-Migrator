"""Minimal PySide6 technician UI for the alpha package workflow."""
from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QFileDialog, QFormLayout, QHBoxLayout,
    QLabel, QLineEdit, QMainWindow, QMessageBox, QPushButton, QPlainTextEdit,
    QProgressBar, QTabWidget, QVBoxLayout, QWidget, QScrollArea,
)

from .credential_workflow import CREDENTIAL_CHECKLIST
from .crypto_package import create_package, inspect_package, restore_package
from .inventory import USER_FOLDERS, build_manifest, discover_outlook
from .manifest import resolve_under
from .preflight import run_preflight
from .reporting import write_job_report


class MigratorWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Pixel IT Profile Migrator — Alpha")
        self.resize(980, 720)
        tabs = QTabWidget()
        tabs.addTab(self._build_create_tab(), "Create migration package")
        tabs.addTab(self._build_restore_tab(), "Restore package")
        tabs.addTab(self._build_credential_tab(), "Outlook & credentials")
        self.setCentralWidget(tabs)
        self.statusBar().showMessage("Alpha build — verify an independent backup before use")

    def _build_create_tab(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page); form = QFormLayout()
        self.source = QLineEdit()
        browse_source = QPushButton("Browse…"); browse_source.clicked.connect(self._choose_source)
        source_row = QHBoxLayout(); source_row.addWidget(self.source); source_row.addWidget(browse_source)
        source_widget = QWidget(); source_widget.setLayout(source_row)
        form.addRow("Source profile / root", source_widget)
        self.output = QLineEdit()
        browse_output = QPushButton("Save package…"); browse_output.clicked.connect(self._choose_output)
        output_row = QHBoxLayout(); output_row.addWidget(self.output); output_row.addWidget(browse_output)
        output_widget = QWidget(); output_widget.setLayout(output_row)
        form.addRow("Package file", output_widget)
        self.job_id = QLineEdit(); self.job_id.setPlaceholderText("Optional job ID; generated if blank")
        form.addRow("Job ID", self.job_id)
        layout.addLayout(form)
        layout.addWidget(QLabel("Select folders relative to the chosen source root:"))
        self.folder_checks = []
        folders = QWidget(); folder_layout = QHBoxLayout(folders)
        for name in USER_FOLDERS:
            check = QCheckBox(name); check.setChecked(name in ("Desktop", "Documents", "Downloads", "Pictures", "Favorites"))
            self.folder_checks.append(check); folder_layout.addWidget(check)
        folder_layout.addStretch(1); layout.addWidget(folders)
        self.outlook_label = QLabel("Outlook discovery: choose a source profile to scan.")
        self.outlook_label.setWordWrap(True); layout.addWidget(self.outlook_label)
        scan_row = QHBoxLayout()
        scan = QPushButton("Scan Outlook data"); scan.clicked.connect(self._scan_outlook)
        preflight = QPushButton("Run preflight scan"); preflight.clicked.connect(self._run_preflight)
        scan_row.addWidget(scan); scan_row.addWidget(preflight); scan_row.addStretch(1); layout.addLayout(scan_row)
        self.passphrase = QLineEdit(); self.passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        self.passphrase.setPlaceholderText("Use a unique passphrase (12+ characters)")
        form.addRow("Package passphrase", self.passphrase)
        self.progress = QProgressBar(); self.progress.setRange(0, 100); layout.addWidget(self.progress)
        self.create_log = QPlainTextEdit(); self.create_log.setReadOnly(True); layout.addWidget(self.create_log, 1)
        create = QPushButton("Create encrypted package"); create.clicked.connect(self._create_package); layout.addWidget(create)
        note = QLabel("ALPHA: selected folders only; Windows metadata, cloud placeholders and very large files require additional handling. Test restores before customer use.")
        note.setWordWrap(True); layout.addWidget(note)
        return page

    def _build_restore_tab(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page); form = QFormLayout()
        self.package_path = QLineEdit(); choose_package = QPushButton("Browse…"); choose_package.clicked.connect(self._choose_package)
        row = QHBoxLayout(); row.addWidget(self.package_path); row.addWidget(choose_package); widget = QWidget(); widget.setLayout(row)
        form.addRow("Encrypted package", widget)
        self.destination = QLineEdit(); choose_destination = QPushButton("Browse…"); choose_destination.clicked.connect(self._choose_destination)
        row2 = QHBoxLayout(); row2.addWidget(self.destination); row2.addWidget(choose_destination); widget2 = QWidget(); widget2.setLayout(row2)
        form.addRow("Destination root", widget2)
        self.restore_passphrase = QLineEdit(); self.restore_passphrase.setEchoMode(QLineEdit.Password)
        form.addRow("Package passphrase", self.restore_passphrase)
        layout.addLayout(form)
        preview = QPushButton("Inspect package and preview conflicts"); preview.clicked.connect(self._preview_restore); layout.addWidget(preview)
        self.restore_log = QPlainTextEdit(); self.restore_log.setReadOnly(True); layout.addWidget(self.restore_log, 1)
        restore = QPushButton("Restore non-conflicting files"); restore.clicked.connect(self._restore); layout.addWidget(restore)
        self.restore_manifest = None
        return page

    def _build_credential_tab(self) -> QWidget:
        page = QWidget(); outer = QVBoxLayout(page)
        intro = QLabel("Use supported vendor workflows. This tool deliberately does not extract Windows passwords, browser secret stores or authentication tokens.")
        intro.setWordWrap(True); outer.addWidget(intro)
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        content = QWidget(); layout = QVBoxLayout(content); self.credential_checks = []
        for item in CREDENTIAL_CHECKLIST:
            check = QCheckBox(item.title)
            check.setToolTip(item.instructions)
            label = QLabel(item.instructions); label.setWordWrap(True)
            layout.addWidget(check); layout.addWidget(label); self.credential_checks.append(check)
        layout.addStretch(1); scroll.setWidget(content); outer.addWidget(scroll)
        save = QPushButton("Show outstanding checklist items"); save.clicked.connect(self._show_credential_status); outer.addWidget(save)
        return page

    def _show_credential_status(self) -> None:
        outstanding = [item.title for item, check in zip(CREDENTIAL_CHECKLIST, self.credential_checks) if not check.isChecked()]
        QMessageBox.information(self, "Credential workflow", "Outstanding items:\n\n" + ("\n".join(outstanding) if outstanding else "All checklist items marked complete.") + "\n\nConfirm each item with the customer/technician; checkboxes are not proof of successful transfer.")

    def _choose_source(self) -> None:
        value = QFileDialog.getExistingDirectory(self, "Select source profile or root")
        if value: self.source.setText(value)

    def _choose_output(self) -> None:
        value, _ = QFileDialog.getSaveFileName(self, "Save encrypted migration package", "PixelIT-Migration.pitpkg", "Pixel IT package (*.pitpkg)")
        if value: self.output.setText(value)

    def _choose_package(self) -> None:
        value, _ = QFileDialog.getOpenFileName(self, "Select migration package", "", "Pixel IT package (*.pitpkg);;All files (*)")
        if value: self.package_path.setText(value)

    def _choose_destination(self) -> None:
        value = QFileDialog.getExistingDirectory(self, "Select destination profile root")
        if value: self.destination.setText(value)

    def _scan_outlook(self) -> None:
        source = Path(self.source.text().strip())
        if not source.is_dir():
            QMessageBox.warning(self, "Source required", "Select a valid source profile/root first."); return
        found = discover_outlook(source)
        lines = [f"PST files ({len(found['pst'])}):", *found["pst"],
                 f"\nSignatures ({len(found['signatures'])} files):", *found["signatures"],
                 f"\nTemplates ({len(found['templates'])} files):", *found["templates"],
                 "\nNotes:", *found["notes"]]
        self.outlook_label.setText("\n".join(lines))

    def _run_preflight(self) -> None:
        source = Path(self.source.text().strip())
        if not source.is_dir():
            QMessageBox.warning(self, "Source required", "Select a valid source profile/root first."); return
        try:
            target = Path(self.output.text().strip()) if self.output.text().strip() else None
            result = run_preflight(source, target)
            lines = [f"Readable files: {result['files_readable']}", f"Readable bytes: {result['bytes_readable']:,}",
                     f"Skipped items: {result['items_skipped']}", f"Advisory ready: {result['ready']}", ""]
            lines.extend(f"{f['severity'].upper()} {f['code']}: {f['path']} — {f['message']}" for f in result['findings'])
            self.create_log.setPlainText("\n".join(lines))
        except Exception as exc:
            QMessageBox.critical(self, "Preflight failed", str(exc))

    def _create_package(self) -> None:
        source = Path(self.source.text().strip()); output = Path(self.output.text().strip())
        passphrase = self.passphrase.text(); selected = [c.text() for c in self.folder_checks if c.isChecked()]
        if not source.is_dir() or not output.name or not selected:
            QMessageBox.warning(self, "Missing information", "Choose a source, output package and at least one folder."); return
        if len(passphrase) < 12:
            QMessageBox.warning(self, "Passphrase too short", "Use a unique passphrase of at least 12 characters."); return
        try:
            preflight = run_preflight(source, output)
            if not preflight["ready"]:
                QMessageBox.warning(self, "Preflight warnings", "Preflight found blocking errors. Review the log and correct them before packaging.")
                self._run_preflight(); return
            manifest = build_manifest(source, selected, self.job_id.text().strip() or None)
            if not manifest.records:
                QMessageBox.warning(self, "No files found", "No files were found in the selected folders."); return
            self.create_log.setPlainText(f"Job: {manifest.job_id}\nFiles: {len(manifest.records)}\nBuilding encrypted package…")
            QApplication.setOverrideCursor(Qt.WaitCursor)
            create_package(source, output, manifest, passphrase,
                           progress=lambda i, total, path: self.progress.setValue(int(i * 100 / max(total, 1))))
            self.create_log.appendPlainText(f"\nPackage created: {output}\nManifest file count: {len(manifest.records)}\nRun a test restore before relying on this package.")
            QMessageBox.information(self, "Package created", "Encrypted package created. Inspect it and perform a test restore to a separate folder.")
        except Exception as exc:
            self.create_log.appendPlainText(f"ERROR: {exc}"); QMessageBox.critical(self, "Package failed", str(exc))
        finally:
            QApplication.restoreOverrideCursor(); self.passphrase.clear()

    def _preview_restore(self) -> None:
        package = Path(self.package_path.text().strip()); destination = Path(self.destination.text().strip())
        passphrase = self.restore_passphrase.text()
        if not package.is_file() or not destination.is_dir() or not passphrase:
            QMessageBox.warning(self, "Missing information", "Choose a package, existing destination root and passphrase."); return
        try:
            manifest = inspect_package(package, passphrase)
            lines = [f"Job ID: {manifest.job_id}", f"Source computer: {manifest.source_computer}", f"Files: {len(manifest.records)}", "", "Preview:"]
            conflicts = 0
            for record in manifest.records:
                target = resolve_under(destination, record.path)
                if target.exists(): conflicts += 1; state = "CONFLICT — will be skipped"
                else: state = "CREATE"
                lines.append(f"{state}: {record.path}")
            lines += ["", f"Conflicts: {conflicts}", "No destination files have been changed."]
            self.restore_log.setPlainText("\n".join(lines)); self.restore_manifest = manifest
        except Exception as exc:
            self.restore_manifest = None; self.restore_log.setPlainText(f"Inspection failed: {exc}")
            QMessageBox.critical(self, "Package inspection failed", str(exc))

    def _restore(self) -> None:
        if self.restore_manifest is None:
            QMessageBox.warning(self, "Preview required", "Inspect the package and preview conflicts first."); return
        if QMessageBox.question(self, "Confirm restore", "Restore files that do not already exist? Existing files will be skipped. Continue?") != QMessageBox.Yes:
            return
        try:
            QApplication.setOverrideCursor(Qt.WaitCursor)
            report = restore_package(Path(self.package_path.text().strip()), Path(self.destination.text().strip()),
                                     self.restore_passphrase.text(), overwrite_paths=set(),
                                     progress=lambda i, total, path: self.statusBar().showMessage(f"Restoring {i}/{total}: {path}"))
            self.restore_log.appendPlainText("\n\nRESTORE REPORT\n" + f"Created: {len(report['created'])}\nSkipped: {len(report['skipped'])}\nErrors: {len(report['errors'])}")
            for section in ("skipped", "errors"):
                for item in report[section]: self.restore_log.appendPlainText(f"{section.upper()}: {item}")
            QMessageBox.information(self, "Restore finished", f"Created {len(report['created'])} files. Skipped {len(report['skipped'])}. Errors {len(report['errors'])}. Review the report.")
            suggested = f"PixelIT-Job-{self.restore_manifest.job_id}-restore-report.json"
            report_path, _ = QFileDialog.getSaveFileName(self, "Save technician report", suggested, "JSON report (*.json)")
            if report_path:
                write_job_report(Path(report_path), job_id=self.restore_manifest.job_id, operation="restore",
                                 source_label=self.restore_manifest.source_computer,
                                 destination_label=Path(self.destination.text().strip()).name,
                                 discovered=len(self.restore_manifest.records), created=report["created"],
                                 overwritten=report["overwritten"], skipped=report["skipped"], errors=report["errors"],
                                 verification=("package-authenticated; restore-errors-present" if report["errors"] else "package-authenticated; restored-files-verified"))
                self.restore_log.appendPlainText(f"\nTechnician report saved: {report_path}")
        except Exception as exc:
            QMessageBox.critical(self, "Restore failed", str(exc))
        finally:
            QApplication.restoreOverrideCursor(); self.restore_passphrase.clear()


def main() -> int:
    app = QApplication(sys.argv); app.setApplicationName("Pixel IT Profile Migrator")
    window = MigratorWindow(); window.show()
    return app.exec()

if __name__ == "__main__":
    raise SystemExit(main())
