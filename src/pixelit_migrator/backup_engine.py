"""Standard, uncompressed backup engine for Windows user profiles."""
from __future__ import annotations

import os
import shutil
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

Progress = Callable[[int, int, str], None]
CHUNK_SIZE = 1024 * 1024
EXCLUDED_PROFILE_NAMES = {"public", "default", "default user", "all users"}


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
    root = drive_root.resolve()
    users = root / "Users"
    if not users.is_dir():
        return []
    profiles = []
    for path in users.iterdir():
        if path.name.casefold() in EXCLUDED_PROFILE_NAMES or _is_reparse(path):
            continue
        if path.is_dir():
            profiles.append(path)
    return sorted(profiles, key=lambda p: p.name.casefold())


def _walk_files(source: Path):
    if _is_reparse(source):
        return
    if source.is_file():
        yield source
        return
    if not source.is_dir():
        return

    def onerror(error: OSError) -> None:
        raise error

    for current, dirs, names in os.walk(source, followlinks=False, onerror=onerror):
        base = Path(current)
        dirs[:] = [name for name in dirs if not _is_reparse(base / name)]
        for name in names:
            candidate = base / name
            if _is_reparse(candidate):
                continue
            if candidate.is_file():
                yield candidate


def inventory(profiles: list[Path], extras: list[Path]) -> tuple[list[BackupItem], int]:
    """Build a stable source inventory and output paths, excluding reparse points."""
    items: list[BackupItem] = []
    seen: set[str] = set()
    for profile in profiles:
        for source in _walk_files(profile):
            rel = source.relative_to(profile).as_posix()
            name = f"Profiles/{profile.name}/{rel}"
            key = name.casefold()
            if key not in seen:
                items.append(BackupItem(source, name))
                seen.add(key)
    used_extra_names: set[str] = set()
    for extra in extras:
        extra = extra.resolve(strict=True)
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
    return items, sum(item.source.stat().st_size for item in items)


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
        for item in items:
            destination_file = output.joinpath(*item.archive_name.split("/"))
            destination_file.parent.mkdir(parents=True, exist_ok=True)
            with item.source.open("rb") as incoming, destination_file.open("wb") as outgoing:
                while True:
                    chunk = incoming.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    outgoing.write(chunk)
                    completed += len(chunk)
                    progress(completed, total_bytes, item.archive_name)
            shutil.copystat(item.source, destination_file, follow_symlinks=False)
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
                    info = zipfile.ZipInfo(item.archive_name)
                    info.compress_type = zipfile.ZIP_STORED
                    info.external_attr = 0o600 << 16
                    with item.source.open("rb") as incoming, archive.open(info, "w", force_zip64=True) as outgoing:
                        while True:
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
