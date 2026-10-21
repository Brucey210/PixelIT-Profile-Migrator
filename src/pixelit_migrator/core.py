"""Compatibility facade for early alpha API and simple integrations."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import socket
from uuid import uuid4

from .crypto_package import create_package, inspect_package, restore_package as _restore_package
from .manifest import FileRecord, MigrationManifest


@dataclass(frozen=True)
class PreviewItem:
    path: str
    status: str
    reason: str = ""


@dataclass(frozen=True)
class RestoreItem:
    path: str
    status: str
    reason: str = ""


def inventory(root: Path) -> list[FileRecord]:
    """Return records for regular files below root; do not follow symlinks."""
    root = Path(root).resolve(strict=True)
    records = []
    for path in root.rglob("*"):
        try:
            if path.is_symlink() or not path.is_file():
                continue
            records.append(FileRecord.from_file(root, path))
        except (OSError, ValueError):
            continue
    return sorted(records, key=lambda r: r.path.casefold())


def create_encrypted_package(source_root: Path, package_path: Path, passphrase: str) -> None:
    root = Path(source_root).resolve(strict=True)
    records = tuple(inventory(root))
    manifest = MigrationManifest(
        job_id=uuid4().hex[:12].upper(),
        created_utc=datetime.now(timezone.utc).isoformat(),
        source_computer=socket.gethostname(),
        records=records,
    )
    create_package(root, Path(package_path), manifest, passphrase)


def preview_package(package_path: Path, passphrase: str, destination_root: Path) -> list[PreviewItem]:
    destination = Path(destination_root).resolve(strict=True)
    manifest = inspect_package(Path(package_path), passphrase)
    result = []
    for record in manifest.records:
        target = destination.joinpath(*record.path.split("/"))
        if target.exists():
            result.append(PreviewItem(record.path, "conflict", "Destination already exists"))
        else:
            result.append(PreviewItem(record.path, "create", "Ready to restore"))
    return result


def restore_package(package_path: Path, passphrase: str, destination_root: Path) -> list[RestoreItem]:
    report = _restore_package(Path(package_path), Path(destination_root), passphrase)
    items = [RestoreItem(path, "restored") for path in report["created"]]
    items.extend(RestoreItem(item["path"], "conflict", item["reason"]) for item in report["skipped"])
    items.extend(RestoreItem(item["path"], "error", item["reason"]) for item in report["errors"])
    return sorted(items, key=lambda item: item.path.casefold())
