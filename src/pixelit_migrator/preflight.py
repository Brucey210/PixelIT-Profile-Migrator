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

    Best-effort scan only: cloud hydration, all reparse-point types, locked-file
    consistency and Windows metadata preservation need dedicated platform support.
    This function does not create directories or modify source/destination files.
    """
    root = Path(source_root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Source root must be a directory")
    findings: list[PreflightFinding] = []
    files = total_bytes = skipped = 0
    for current, dirs, names in os.walk(root, followlinks=False):
        base = Path(current)
        kept_dirs = []
        for name in dirs:
            path = base / name
            try:
                attrs = getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0) if os.name == "nt" else 0
                if path.is_symlink() or (attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
                    skipped += 1
                    findings.append(PreflightFinding(str(path), "warning", "REPARSE_OR_SYMLINK_SKIPPED", "Directory link/reparse point was not followed"))
                    continue
                kept_dirs.append(name)
            except OSError as exc:
                skipped += 1
                findings.append(PreflightFinding(str(path), "error", "DIRECTORY_UNREADABLE", str(exc)))
        dirs[:] = kept_dirs
        for name in names:
            path = base / name
            try:
                attrs = getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0) if os.name == "nt" else 0
                if path.is_symlink() or not path.is_file() or (attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
                    skipped += 1
                    findings.append(PreflightFinding(str(path), "warning", "NON_REGULAR_OR_REPARSE", "Non-regular, link or reparse-point file was skipped"))
                    continue
                size = path.stat().st_size
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
            if not target_parent.is_dir():
                raise FileNotFoundError("Package destination directory does not exist")
            free = shutil.disk_usage(target_parent).free
            required = int(total_bytes * 1.10) + 16 * 1024 * 1024
            if free < required:
                findings.append(PreflightFinding(str(target_parent), "error", "INSUFFICIENT_SPACE",
                                                 f"Estimated required bytes: {required}; free bytes: {free}"))
        except OSError as exc:
            findings.append(PreflightFinding(str(target_parent), "error", "TARGET_UNAVAILABLE", str(exc)))
    return {"source_root": str(root), "files_readable": files, "bytes_readable": total_bytes,
            "items_skipped": skipped, "findings": [asdict(item) for item in findings],
            "ready": not any(item.severity == "error" for item in findings),
            "notice": "Advisory only; use a verified independent backup and platform-specific validation."}
