"""Strict manifest models and safe relative path validation."""
from __future__ import annotations

import hashlib
import json
import os
import stat as stat_module
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

MANIFEST_VERSION = 1


def is_link_or_reparse(path: Path) -> bool:
    """Detect symlinks and Windows reparse points without following the final path."""
    try:
        if path.is_symlink():
            return True
        if os.name == "nt":
            attrs = getattr(path.lstat(), "st_file_attributes", 0)
            return bool(attrs & getattr(stat_module, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    except OSError:
        return True
    return False


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_relative_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("Invalid empty or NUL-containing relative path")
    normal = value.replace("\\", "/")
    win = PureWindowsPath(value)
    posix = PurePosixPath(normal)
    parts = normal.split("/")
    if win.is_absolute() or win.drive or posix.is_absolute() or ":" in value:
        raise ValueError("Absolute or drive-qualified paths are not allowed")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError("Unsafe path segment")
    if normal.startswith("//"):
        raise ValueError("UNC paths are not allowed")
    return normal


@dataclass(frozen=True)
class FileRecord:
    path: str
    size: int
    sha256: str

    @classmethod
    def from_file(cls, root: Path, file_path: Path) -> "FileRecord":
        relative = file_path.relative_to(root).as_posix()
        validate_relative_path(relative)
        if is_link_or_reparse(file_path) or not file_path.is_file():
            raise ValueError(f"Not a regular file: {relative}")
        stat_result = file_path.stat()
        return cls(relative, stat_result.st_size, sha256_file(file_path))

    def validate(self) -> None:
        validate_relative_path(self.path)
        if self.size < 0:
            raise ValueError("Negative file size")
        if len(self.sha256) != 64 or any(c not in "0123456789abcdef" for c in self.sha256.lower()):
            raise ValueError(f"Invalid SHA-256 for {self.path}")


@dataclass(frozen=True)
class MigrationManifest:
    job_id: str
    created_utc: str
    source_computer: str
    records: tuple[FileRecord, ...]
    version: int = MANIFEST_VERSION

    def to_bytes(self) -> bytes:
        payload = {"version": self.version, "job_id": self.job_id, "created_utc": self.created_utc,
                   "source_computer": self.source_computer, "records": [asdict(record) for record in self.records]}
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "MigrationManifest":
        try:
            obj: dict[str, Any] = json.loads(data.decode("utf-8"))
            if not isinstance(obj, dict) or obj.get("version") != MANIFEST_VERSION:
                raise ValueError("Unsupported or invalid manifest version")
            records = tuple(FileRecord(**row) for row in obj["records"])
            for record in records:
                record.validate()
            paths = [r.path.casefold() for r in records]
            if len(paths) != len(set(paths)):
                raise ValueError("Duplicate paths in manifest")
            return cls(str(obj["job_id"]), str(obj["created_utc"]), str(obj["source_computer"]), records, int(obj["version"]))
        except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Invalid migration manifest") from exc


def resolve_under(root: Path, relative: str, *, reject_symlinks: bool = True) -> Path:
    """Resolve a manifest path beneath root and reject existing links/reparse points.

    This check is not a race-free sandbox. Windows production builds still need native
    handle-based reparse-point checks and handle-relative writes.
    """
    relative = validate_relative_path(relative)
    root = root.resolve(strict=True)
    candidate = root.joinpath(*relative.split("/"))
    current = root
    if reject_symlinks:
        for segment in relative.split("/"):
            current = current / segment
            if is_link_or_reparse(current):
                raise ValueError(f"Link/reparse-point component rejected: {relative}")
    resolved = candidate.resolve(strict=False)
    if os.path.commonpath([str(root), str(resolved)]) != str(root):
        raise ValueError("Path escapes selected root")
    return candidate
