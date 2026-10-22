"""Standard, uncompressed backup engine for Windows user profiles."""
from __future__ import annotations

import os
import shutil
import threading
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

Progress = Callable[[int, int, str], None]
CHUNK_SIZE = 1024 * 1024
EXCLUDED_PROFILE_NAMES = {"public", "default", "default user", "all users"}


class BackupCancelled(Exception):
    """Raised when the operator cancels a running backup."""


def _check_cancel(cancel_event: threading.Event | None) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise BackupCancelled("Backup cancelled by the operator.")


@dataclass(frozen=True)
class BackupItem:
    source: Path
    archive_name: str


def _is_reparse(path: Path) -> bool:
    try:
        if os.name == "nt":
            return bool(path.stat(follow_symlinks=False).st_file_attributes & 0x400)
        return path.is_symlink()
    except OSError:
        return True


def discover_profiles(drive_root: Path) -> list[Path]:
    """Discover profile directories in <drive>\\Users without following links."""
    users = drive_root.resolve() / "Users"
    if not users.is_dir():
        return []
    profiles = []
    try:
        for path in users.iterdir():
            if path.name.casefold() in EXCLUDED_PROFILE_NAMES or _is_reparse(path):
                continue
            try:
                if path.is_dir():
                    profiles.append(path)
            except OSError:
                continue
    except OSError:
        return profiles
    return sorted(profiles, key=lambda p: p.name.casefold())


def _walk_files(source: Path):
    try:
        if _is_reparse(source):
            return
        if source.is_file():
            yield source
            return
        if not source.is_dir():
            return
    except OSError:
        return
    # Windows protects some profile subfolders (e.g. ElevatedDiagnostics).
    # os.walk skips inaccessible subtrees when no onerror callback is supplied.
    for current, dirs, names in os.walk(source, followlinks=False):
        base = Path(current)
        dirs[:] = [name for name in dirs if not _is_reparse(base / name)]
        for name in names:
            candidate = base / name
            if _is_reparse(candidate):
                continue
            try:
                if candidate.is_file():
                    yield candidate
            except OSError:
                continue


def _profile_root(selected: Path) -> Path:
    if selected.parent.name.casefold() == "users":
        return selected
    if selected.parent.parent.name.casefold() == "users":
        return selected.parent
    for parent in selected.parents:
        if parent.parent.name.casefold() == "users":
            return parent
    return selected


def inventory(profiles: list[Path], extras: list[Path]) -> tuple[list[BackupItem], int]:
    """Build a stable source inventory and output paths, skipping inaccessible files."""
    items: list[BackupItem] = []
    seen: set[str] = set()
    for selected in profiles:
        root = _profile_root(selected)
        for source in _walk_files(selected):
            rel = source.relative_to(root).as_posix()
            name = f"Profiles/{root.name}/{rel}"
            key = name.casefold()
            if key not in seen:
                items.append(BackupItem(source, name))
                seen.add(key)
    used_extra_names: set[str] = set()
    for extra in extras:
        try:
            extra = extra.resolve(strict=True)
        except OSError:
            continue
        base = extra.name or extra.drive.replace(":", "")
        folder_name = base
        counter = 2
        while folder_name.casefold() in used_extra_names:
            folder_name = f"{base} ({counter})"
            counter += 1
        used_extra_names.add(folder_name.casefold())
        for source in _walk_files(extra):
            rel = source.relative_to(extra).as_posix() if extra.is_dir() else source.name
            name = f"Additional/{folder_name}/{rel}"
            key = name.casefold()
            if key not in seen:
                items.append(BackupItem(source, name))
                seen.add(key)
    items.sort(key=lambda item: item.archive_name.casefold())
    readable_items = []
    total_bytes = 0
    for item in items:
        try:
            total_bytes += item.source.stat().st_size
            readable_items.append(item)
        except OSError:
            continue
    return readable_items, total_bytes


def format_bytes(value: int) -> str:
    amount = float(max(0, value))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if amount < 1024 or unit == "TB":
            return f"{int(amount):,} B" if unit == "B" else f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} TB"


def create_backup(
    profiles: list[Path],
    extras: list[Path],
    destination: Path,
    output_format: str,
    progress: Progress | None = None,
    cancel_event: threading.Event | None = None,
) -> dict:
    """Create a regular directory-tree backup or standard uncompressed ZIP."""
    progress = progress or (lambda done, total, name: None)
    profiles = [p.resolve(strict=True) for p in profiles]
    extras = [p.resolve(strict=True) for p in extras]
    items, total_bytes = inventory(profiles, extras)
    if not items:
        raise ValueError("No readable files were found in the selected profiles/folders.")
    target = destination.expanduser().resolve()
    for source in profiles + extras:
        if target == source or source in target.parents:
            raise ValueError(f"Backup destination must be outside the selected source: {source}")

    if output_format == "folder":
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        output = target / f"PixelIT-Backup-{stamp}"
        output.mkdir(parents=True, exist_ok=False)
        completed = 0
        try:
            for item in items:
                _check_cancel(cancel_event)
                destination_file = output.joinpath(*item.archive_name.split("/"))
                destination_file.parent.mkdir(parents=True, exist_ok=True)
                with item.source.open("rb") as incoming, destination_file.open("wb") as outgoing:
                    while True:
                        _check_cancel(cancel_event)
                        chunk = incoming.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        outgoing.write(chunk)
                        completed += len(chunk)
                        progress(completed, total_bytes, item.archive_name)
                shutil.copystat(item.source, destination_file, follow_symlinks=False)
        except Exception:
            shutil.rmtree(output, ignore_errors=True)
            raise
    elif output_format == "zip":
        output = target
        if output.suffix.casefold() != ".zip":
            output = output.with_suffix(".zip")
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_name(output.name + ".partial")
        completed = 0
        try:
            with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
                for item in items:
                    _check_cancel(cancel_event)
                    info = zipfile.ZipInfo(item.archive_name)
                    info.compress_type = zipfile.ZIP_STORED
                    info.external_attr = 0o600 << 16
                    with item.source.open("rb") as incoming, archive.open(info, "w", force_zip64=True) as outgoing:
                        while True:
                            _check_cancel(cancel_event)
                            chunk = incoming.read(CHUNK_SIZE)
                            if not chunk:
                                break
                            outgoing.write(chunk)
                            completed += len(chunk)
                            progress(completed, total_bytes, item.archive_name)
            os.replace(temporary, output)
        finally:
            temporary.unlink(missing_ok=True)
    else:
        raise ValueError("Unsupported backup format. Choose folder or zip.")

    return {"output": output, "files": len(items), "bytes": total_bytes, "format": output_format}
