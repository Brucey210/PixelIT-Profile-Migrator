"""Read-only preflight checks before creating a migration package."""
from __future__ import annotations

import os
import shutil
import stat
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass(frozen=True)
class PreflightFinding:
    path: str
    severity: str
    code: str
    message: str
    size_bytes: int = 0


def run_preflight(source_root: Path, package_target: Path | None = None) -> dict:
    """Inventory readable regular files and surface common migration hazards.

    This is a best-effort scan. It cannot prove files are unlocked, hydrated from
    cloud storage, or fully preserve Windows metadata; the Windows release needs
    dedicated reparse-point and cloud-provider API support.
    """
    root = Path(source_root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Source root must be a directory")
    findings: list[PreflightFinding] = []
    files = 0
    total_bytes = 0
    skipped = 0
    for current, dirs, names in os.walk(root, followlinks=False):
        base = Path(current)
        kept_dirs = []
        for name in dirs:
            path = base / name
            try:
                if path.is_symlink():
                    skipped += 1
                    findings.append(PreflightFinding(str(path), "warning", "SYMLINK_SKIPPED", "Symbolic-link directory was not followed"))
                    continue
                if os.name == "nt":
                    attrs = getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0)
                    if attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
                        skipped += 1
                        findings.append(PreflightFinding(str(path), "warning", "REPARSE_POINT_SKIPPED", "Reparse-point directory requires Windows-specific handling"))
                        continue
                kept_dirs.append(name)
            except OSError as exc:
                skipped += 1
                findings.append(PreflightFinding(str(path), "error", "DIRECTORY_UNREADABLE", str(exc)))
        dirs[:] = kept_dirs
        for name in names:
            path = base / name
            try:
                if path.is_symlink() or not path.is_file():
                    skipped += 1
                    findings.append(PreflightFinding(str(path), "warning", "NON_REGULAR_FILE", "Non-regular or symbolic-link file was skipped"))
                    continue
                if os.name == "nt":
                    attrs = getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0)
                    if attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
                        skipped += 1
                        findings.append(PreflightFinding(str(path), "warning", "REPARSE_POINT_SKIPPED", "Reparse-point file requires Windows-specific handling"))
                        continue
                size = path.stat().st_size
                # Read one byte to detect obvious access failures; a zero-byte file is still valid.
                with path.open("rb") as stream:
                    stream.read(1)
                files += 1
                total_bytes += size
            except OSError as exc:
                skipped += 1
                findings.append(PreflightFinding(str(path), "error", "FILE_UNREADABLE", str(exc)))
    if package_target is not None:
        target_parent = Path(package_target).expanduser().absolute().parent
        try:
            target_parent.mkdir(parents=True, exist_ok=True)
            free = shutil.disk_usage(target_parent).free
            # Encryption overhead + manifest/archive overhead reserve.
            required = int(total_bytes * 1.10) + 16 * 1024 * 1024
            if free < required:
                findings.append(PreflightFinding(str(target_parent), "error", "INSUFFICIENT_SPACE",
                                                 f"Estimated package space {required} bytes; free space {free} bytes"))
        except OSError as exc:
            findings.append(PreflightFinding(str(target_parent), "error", "TARGET_UNAVAILABLE", str(exc)))
    return {
        "source_root": str(root),
        "files_readable": files,
        "bytes_readable": total_bytes,
        "items_skipped": skipped,
        "findings": [asdict(item) for item in findings],
        "ready": not any(item.severity == "error" for item in findings),
        "notice": "Preflight is advisory and does not replace a verified backup or Windows-specific migration tests.",
    }
