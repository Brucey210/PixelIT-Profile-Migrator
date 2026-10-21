"""Read-only preflight checks before creating a migration package."""
from __future__ import annotations

import os
import shutil
import stat
from dataclasses import dataclass, asdict
from pathlib import Path

from .manifest import is_link_or_reparse, resolve_under


@dataclass(frozen=True)
class PreflightFinding:
    path: str
    severity: str
    code: str
    message: str
    size_bytes: int = 0


def run_preflight(
    source_root: Path,
    package_target: Path | None = None,
    *,
    selected_paths: list[str] | None = None,
) -> dict:
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
    seen_files: set[str] = set()
    walk_roots: list[Path] = []
    direct_files: list[Path] = []
    if selected_paths is None:
        walk_roots = [root]
    else:
        for relative in selected_paths:
            try:
                candidate = resolve_under(root, relative)
                if is_link_or_reparse(candidate):
                    skipped += 1
                    findings.append(PreflightFinding(str(candidate), "warning", "REPARSE_OR_SYMLINK_SKIPPED",
                                                     "Selected link/reparse point was not followed"))
                elif candidate.is_dir():
                    walk_roots.append(candidate)
                elif candidate.is_file():
                    direct_files.append(candidate)
                else:
                    skipped += 1
                    findings.append(PreflightFinding(str(candidate), "warning", "SELECTED_PATH_MISSING",
                                                     "Selected path no longer exists"))
            except (OSError, ValueError) as exc:
                skipped += 1
                findings.append(PreflightFinding(str(relative), "error", "INVALID_SELECTED_PATH", str(exc)))

    def check_file(path: Path) -> None:
        nonlocal files, total_bytes, skipped
        identity = str(path.resolve(strict=False)).casefold()
        if identity in seen_files:
            return
        seen_files.add(identity)
        try:
            if is_link_or_reparse(path) or not path.is_file():
                skipped += 1
                findings.append(PreflightFinding(str(path), "warning", "NON_REGULAR_OR_REPARSE",
                                                 "Non-regular, link or reparse-point file was skipped"))
                return
            size = path.stat().st_size
            with path.open("rb") as stream:
                stream.read(1)
            files += 1
            total_bytes += size
        except OSError as exc:
            skipped += 1
            findings.append(PreflightFinding(str(path), "error", "FILE_UNREADABLE", str(exc)))

    for path in direct_files:
        check_file(path)

    for scan_root in walk_roots:
        for current, dirs, names in os.walk(scan_root, followlinks=False):
            base = Path(current)
            kept_dirs = []
            for name in dirs:
                path = base / name
                if is_link_or_reparse(path):
                    skipped += 1
                    findings.append(PreflightFinding(str(path), "warning", "REPARSE_OR_SYMLINK_SKIPPED",
                                                     "Directory link/reparse point was not followed"))
                else:
                    kept_dirs.append(name)
            dirs[:] = kept_dirs
            for name in names:
                check_file(base / name)
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
