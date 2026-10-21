"""Minimal PySide6 technician UI for the alpha package workflow."""
from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import QObject, QThread, Qt, Signal, Slot
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QFileDialog, QFormLayout, QHBoxLayout,
    QLabel, QLineEdit, QMainWindow, QMessageBox, QPushButton, QPlainTextEdit,
    QProgressBar, QTabWidget, QVBoxLayout, QWidget, QScrollArea,
)

from .credential_workflow import CREDENTIAL_CHECKLIST
from .crypto_package import create_package, inspect_package, restore_package
from .inventory import USER_FOLDERS, build_manifest, discover_outlook, outlook_relative_paths
from .manifest import resolve_under
from .preflight import run_preflight
from .reporting import write_job_report


class _OperationWorker(QObject):
    progress = Signal(int, int, str)
    succeeded = Signal(object)
    failed = Signal(str)
    finished = Signal()

    def __init__(self, operation) -> None:
        super().__init__()
        self.operation = operation

    @Slot()
    def run(self) -> None:
        try:
            self.succeeded.emit(self.operation(self.progress.emit))
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            self.finished.emit()


class MigratorWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self._active_thread = None
        self._active_worker = None
        self._pending_restore_manifest = None
        self._pending_restore_destination = None
        self.setWindowTitle("Pixel IT Profile Migrator — Alpha")
        self.resize(980, 720)
        tabs = QTabWidget()
        tabs.addTab(self._build_create_tab(), "Create migration package")
        tabs.addTab(self._build_restore_tab(), "Restore package")
        tabs.addTab(self._build_credential_tab(), "Outlook & credentials")
        self.setCentralWidget(tabs)
        self.statusBar().showMessage("Alpha build — verify an independent backup before use")


    def closeEvent(self, event) -> None:
        if self._active_thread is not None:
            QMessageBox.warning(
                self, "Migration in progress",
                "Wait for the current operation to finish before closing Pixel IT Profile Migrator."
            )
            event.ignore()
            return
        event.accept()

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
        self.include_outlook = QCheckBox("Include discovered Outlook PSTs, signatures and templates")
        self.include_outlook.setChecked(True)
        layout.addWidget(self.include_outlook)
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
        self.create_button = create
        note = QLabel("ALPHA: selected folders plus discovered Outlook PSTs/signatures/templates when enabled. Windows metadata and cloud placeholders require additional handling. Test restores before customer use.")
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
        self.restore_button = restore
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
            QMessageBox.warning(self, "Source required", "Select a valid source profile/root first.")
            return
        try:
            target = Path(self.output.text().strip()) if self.output.text().strip() else None
            selected_paths = [check.text() for check in self.folder_checks if check.isChecked()]
            if self.include_outlook.isChecked():
                selected_paths.extend(outlook_relative_paths(source))
            if not selected_paths:
                QMessageBox.warning(self, "Selection required", "Select folders or enable Outlook data inclusion.")
                return
        except Exception as exc:
            QMessageBox.critical(self, "Preflight setup failed", str(exc))
            return
        self.create_log.setPlainText("Preflight scan running in the background…")

        def operation(progress):
            return run_preflight(source, target, selected_paths=selected_paths)

        self._start_worker(operation, self._preflight_succeeded, self._preflight_failed)

    def _preflight_succeeded(self, result: dict) -> None:
        lines = [
            f"Readable files: {result['files_readable']}",
            f"Readable bytes: {result['bytes_readable']:,}",
            f"Skipped items: {result['items_skipped']}",
            f"Advisory ready: {result['ready']}",
            "",
        ]
        lines.extend(
            f"{item['severity'].upper()} {item['code']}: {item['path']} — {item['message']}"
            for item in result["findings"]
        )
        self.create_log.setPlainText("\n".join(lines))

    def _preflight_failed(self, message: str) -> None:
        self.create_log.setPlainText(f"Preflight failed: {message}")
        QMessageBox.critical(self, "Preflight failed", message)

    def _start_worker(self, operation, on_success, on_failure, progress_handler=None) -> None:
        if self._active_thread is not None:
            QMessageBox.warning(self, "Operation in progress", "Wait for the current migration operation to finish.")
            return
        self.centralWidget().setEnabled(False)
        QApplication.setOverrideCursor(Qt.WaitCursor)
        thread = QThread(self)
        worker = _OperationWorker(operation)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.succeeded.connect(on_success)
        worker.failed.connect(on_failure)
        if progress_handler is not None:
            worker.progress.connect(progress_handler)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(self._worker_finished)
        thread.finished.connect(thread.deleteLater)
        self._active_thread = thread
        self._active_worker = worker
        thread.start()

    @Slot()
    def _worker_finished(self) -> None:
        QApplication.restoreOverrideCursor()
        self.centralWidget().setEnabled(True)
        self.progress.setRange(0, 100)
        self._active_thread = None
        self._active_worker = None

    @Slot(int, int, str)
    def _create_progress(self, index: int, total: int, path: str) -> None:
        if total <= 0:
            self.progress.setRange(0, 0)
            self.statusBar().showMessage(path)
            return
        if self.progress.maximum() == 0:
            self.progress.setRange(0, 100)
        self.progress.setValue(int(index * 100 / total))
        self.statusBar().showMessage(f"Packaging {index}/{total}: {path}")

    @Slot(int, int, str)
    def _restore_progress(self, index: int, total: int, path: str) -> None:
        self.statusBar().showMessage(f"Restoring {index}/{total}: {path}")

    def _create_package(self) -> None:
        source = Path(self.source.text().strip())
        output = Path(self.output.text().strip())
        passphrase = self.passphrase.text()
        selected = [check.text() for check in self.folder_checks if check.isChecked()]
        include_outlook = self.include_outlook.isChecked()
        job_id = self.job_id.text().strip() or None
        if not source.is_dir() or not output.name or (not selected and not include_outlook):
            QMessageBox.warning(
                self, "Missing information",
                "Choose a source, output package and at least one folder or discovered Outlook data."
            )
            return
        if len(passphrase) < 12:
            QMessageBox.warning(self, "Passphrase too short", "Use a unique passphrase of at least 12 characters.")
            return
        self.progress.setValue(0)
        self.create_log.setPlainText("Preflight and inventory scan running…")

        def operation(progress):
            progress(0, 0, "Running preflight checks…")
            selected_paths = list(selected)
            if include_outlook:
                selected_paths.extend(outlook_relative_paths(source))
            preflight = run_preflight(source, output, selected_paths=selected_paths)
            if not preflight["ready"]:
                details = "\n".join(
                    f"{item['severity'].upper()} {item['code']}: {item['path']} — {item['message']}"
                    for item in preflight["findings"]
                )
                raise ValueError("Preflight found blocking errors. Correct these before packaging:\n" + details)
            progress(0, 0, "Inventorying and hashing selected files…")
            manifest = build_manifest(source, selected_paths, job_id)
            if not manifest.records:
                raise ValueError("No files were found in the selected folders or Outlook locations.")
            create_package(source, output, manifest, passphrase, progress=progress)
            return {"manifest": manifest, "output": output, "preflight": preflight}

        self._start_worker(operation, self._create_succeeded, self._create_failed, self._create_progress)

    def _create_failed(self, message: str) -> None:
        self.passphrase.clear()
        self.create_log.appendPlainText(f"\nERROR: {message}")
        QMessageBox.critical(self, "Package failed", message)

    def _create_succeeded(self, result: dict) -> None:
        self.passphrase.clear()
        manifest = result["manifest"]
        output = result["output"]
        findings = result["preflight"]["findings"]
        warnings = [item for item in findings if item["severity"] == "warning"]
        self.create_log.appendPlainText(
            f"\nPackage created: {output}\nManifest file count: {len(manifest.records)}"
            f"\nPreflight warnings: {len(warnings)}"
            "\nRun a test restore before relying on this package."
        )
        for item in warnings:
            self.create_log.appendPlainText(
                f"WARNING {item['code']}: {item['path']} — {item['message']}"
            )
        message = "Encrypted package created. Inspect it and perform a test restore to a separate folder."
        if warnings:
            QMessageBox.warning(
                self, "Package created with warnings",
                message + f"\n\nPreflight reported {len(warnings)} warning(s). Review the log before using this package."
            )
        else:
            QMessageBox.information(self, "Package created", message)
        suggested = f"PixelIT-Job-{manifest.job_id}-package-report.json"
        report_path, _ = QFileDialog.getSaveFileName(
            self, "Save technician package report", suggested, "JSON report (*.json)"
        )
        if report_path:
            write_job_report(
                Path(report_path), job_id=manifest.job_id, operation="package-create",
                source_label=manifest.source_computer, destination_label=output.name,
                discovered=len(manifest.records),
                skipped=[
                    {"path": item["path"], "reason": item["message"], "code": item["code"]}
                    for item in warnings
                ],
                verification=("package-created-with-preflight-warnings; test-restore-required" if warnings
                              else "package-created; test-restore-required")
            )
            self.create_log.appendPlainText(f"\nTechnician report saved: {report_path}")

    def _preview_restore(self) -> None:
        package = Path(self.package_path.text().strip())
        destination = Path(self.destination.text().strip())
        passphrase = self.restore_passphrase.text()
        if not package.is_file() or not destination.is_dir() or not passphrase:
            QMessageBox.warning(
                self, "Missing information",
                "Choose a package, existing destination root and passphrase."
            )
            return
        self.restore_manifest = None
        self.restore_log.setPlainText("Authenticating package and checking destination conflicts…")

        def operation(progress):
            manifest = inspect_package(package, passphrase)
            lines = [
                f"Job ID: {manifest.job_id}",
                f"Source computer: {manifest.source_computer}",
                f"Files: {len(manifest.records)}",
                "",
                "Preview:",
            ]
            conflicts = 0
            for record in manifest.records:
                target = resolve_under(destination, record.path)
                if target.exists():
                    conflicts += 1
                    state = "CONFLICT — will be skipped"
                else:
                    state = "CREATE"
                lines.append(f"{state}: {record.path}")
            lines.extend(["", f"Conflicts: {conflicts}", "No destination files have been changed."])
            return {"manifest": manifest, "preview": "\n".join(lines)}

        self._start_worker(operation, self._preview_succeeded, self._preview_failed)

    def _preview_succeeded(self, result: dict) -> None:
        self.restore_manifest = result["manifest"]
        self.restore_log.setPlainText(result["preview"])

    def _preview_failed(self, message: str) -> None:
        self.restore_manifest = None
        self.restore_log.setPlainText(f"Inspection failed: {message}")
        QMessageBox.critical(self, "Package inspection failed", message)

    def _restore(self) -> None:
        if self.restore_manifest is None:
            QMessageBox.warning(self, "Preview required", "Inspect the package and preview conflicts first.")
            return
        if QMessageBox.question(
            self, "Confirm restore",
            "Restore files that do not already exist? Existing files will be skipped. Continue?"
        ) != QMessageBox.Yes:
            return
        package = Path(self.package_path.text().strip())
        destination = Path(self.destination.text().strip())
        passphrase = self.restore_passphrase.text()
        manifest = self.restore_manifest
        self.restore_log.appendPlainText("\nRestore started…")

        def operation(progress):
            return restore_package(package, destination, passphrase, overwrite_paths=set(), progress=progress)

        self._pending_restore_manifest = manifest
        self._pending_restore_destination = destination
        self._start_worker(operation, self._restore_succeeded_from_worker,
                           self._restore_failed, self._restore_progress)

    def _restore_succeeded_from_worker(self, report: dict) -> None:
        # A bound QObject slot ensures UI updates run on the GUI thread.
        self._restore_succeeded(
            report, self._pending_restore_manifest, self._pending_restore_destination
        )

    def _restore_failed(self, message: str) -> None:
        self.restore_passphrase.clear()
        self.restore_log.appendPlainText(f"\nRESTORE FAILED: {message}")
        QMessageBox.critical(self, "Restore failed", message)

    def _restore_succeeded(self, report: dict, manifest, destination: Path) -> None:
        self.restore_passphrase.clear()
        self.restore_log.appendPlainText(
            "\n\nRESTORE REPORT\n"
            + f"Created: {len(report['created'])}\nSkipped: {len(report['skipped'])}\nErrors: {len(report['errors'])}"
        )
        for section in ("skipped", "errors"):
            for item in report[section]:
                self.restore_log.appendPlainText(f"{section.upper()}: {item}")
        QMessageBox.information(
            self, "Restore finished",
            f"Created {len(report['created'])} files. Skipped {len(report['skipped'])}. "
            f"Errors {len(report['errors'])}. Review the report."
        )
        suggested = f"PixelIT-Job-{manifest.job_id}-restore-report.json"
        report_path, _ = QFileDialog.getSaveFileName(
            self, "Save technician report", suggested, "JSON report (*.json)"
        )
        if report_path:
            write_job_report(
                Path(report_path), job_id=manifest.job_id, operation="restore",
                source_label=manifest.source_computer, destination_label=destination.name,
                discovered=len(manifest.records), created=report["created"],
                overwritten=report["overwritten"], skipped=report["skipped"], errors=report["errors"],
                verification=("package-authenticated; restore-errors-present" if report["errors"]
                              else "package-authenticated; restored-files-verified")
            )
            self.restore_log.appendPlainText(f"\nTechnician report saved: {report_path}")


def main() -> int:
    app = QApplication(sys.argv); app.setApplicationName("Pixel IT Profile Migrator")
    window = MigratorWindow(); window.show()
    return app.exec()

if __name__ == "__main__":
    raise SystemExit(main())
