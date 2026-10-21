from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import tempfile
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

CHUNK_SIZE = 1024 * 1024
FORMAT_VERSION = 1


@dataclass(frozen=True)
class FileRecord:
    relative_path: str
    size: int
    sha256: str


@dataclass(frozen=True)
class PreviewItem:
    relative_path: str
    status: str
    reason: str = ""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_relative(value: str) -> PurePosixPath:
    path = PurePosixPath(value.replace("\\", "/"))
    if not value or "\x00" in value or path.is_absolute() or any(p in ("", ".", "..") for p in path.parts):
        raise ValueError(f"Unsafe relative path: {value!r}")
    if ":" in value or value.startswith(("/", "\\\\")):
        raise ValueError(f"Unsafe relative path: {value!r}")
    return path


def _inside(root: Path, relative: str) -> Path:
    parts = _safe_relative(relative).parts
    root = root.resolve(strict=True)
    current = root
    for part in parts:
        current = current / part
        # Avoid traversing existing symlinks/reparse-like symlinks.
        if current.is_symlink():
            raise ValueError(f"Symlink path is not supported: {relative}")
    resolved = current.resolve(strict=False)
    if not resolved.is_relative_to(root):
        raise ValueError(f"Path escapes root: {relative}")
    return current


def inventory(root: Path, selected: Iterable[str] | None = None) -> list[FileRecord]:
    """Inventory regular files below root. Symlinks are skipped, not followed."""
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Source must be a directory")
    allowed = set(selected) if selected is not None else None
    records: list[FileRecord] = []
    for current, dirs, names in os.walk(root, followlinks=False):
        base = Path(current)
        dirs[:] = [d for d in dirs if not (base / d).is_symlink()]
        for name in names:
            path = base / name
            if path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            if allowed is not None and not any(relative == x or relative.startswith(x.rstrip("/") + "/") for x in allowed):
                continue
            records.append(FileRecord(relative, path.stat().st_size, sha256_file(path)))
    return sorted(records, key=lambda r: r.relative_path.casefold())


def create_encrypted_package(source_root: Path, output_file: Path, passphrase: str,
                             selected: Iterable[str] | None = None) -> list[FileRecord]:
    """Create an AES-256-GCM encrypted ZIP payload. Never deletes source files."""
    if not passphrase:
        raise ValueError("A non-empty passphrase is required")
    source_root = source_root.resolve(strict=True)
    output_file = output_file.resolve(strict=False)
    if output_file == source_root or source_root in output_file.parents:
        raise ValueError("Package output must not be inside the source tree")
    records = inventory(source_root, selected)
    if not records:
        raise ValueError("No eligible files selected")
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)
    key = kdf.derive(passphrase.encode("utf-8"))
    output_file.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".pixelit-", suffix=".tmp", dir=output_file.parent)
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        with tempfile.TemporaryDirectory(prefix="pixelit-stage-") as staging:
            staged = Path(staging) / "payload.zip"
            with zipfile.ZipFile(staged, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
                for record in records:
                    src = _inside(source_root, record.relative_path)
                    if src.stat().st_size != record.size or sha256_file(src) != record.sha256:
                        raise IOError(f"Source changed during packaging: {record.relative_path}")
                    archive.write(src, arcname=record.relative_path)
                manifest = {
                    "format_version": FORMAT_VERSION,
                    "records": [asdict(r) for r in records],
                }
                archive.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
            plaintext = staged.read_bytes()
            ciphertext = AESGCM(key).encrypt(nonce, plaintext, b"PixelIT-Profile-Migrator-v1")
            with temp_path.open("wb") as out:
                out.write(b"PITM")
                out.write(bytes([FORMAT_VERSION]))
                out.write(salt)
                out.write(nonce)
                out.write(ciphertext)
                out.flush()
                os.fsync(out.fileno())
        os.replace(temp_path, output_file)
    finally:
        temp_path.unlink(missing_ok=True)
    return records


def _decrypt_package(package_file: Path, passphrase: str) -> tuple[bytes, dict]:
    raw = package_file.read_bytes()
    if len(raw) < 33 or raw[:4] != b"PITM" or raw[4] != FORMAT_VERSION:
        raise ValueError("Unsupported or invalid package format")
    salt, nonce, ciphertext = raw[5:21], raw[21:33], raw[33:]
    key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode("utf-8"))
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, b"PixelIT-Profile-Migrator-v1")
    return plaintext, {"format_version": FORMAT_VERSION}


def preview_package(package_file: Path, passphrase: str, destination_root: Path) -> list[PreviewItem]:
    plaintext, _ = _decrypt_package(package_file, passphrase)
    destination_root = destination_root.resolve(strict=True)
    results: list[PreviewItem] = []
    with tempfile.TemporaryDirectory(prefix="pixelit-preview-") as tmp:
        archive_path = Path(tmp) / "payload.zip"
        archive_path.write_bytes(plaintext)
        with zipfile.ZipFile(archive_path) as archive:
            names = set(archive.namelist())
            if "manifest.json" not in names:
                raise ValueError("Package manifest is missing")
            manifest = json.loads(archive.read("manifest.json"))
            for raw in manifest.get("records", []):
                record = FileRecord(**raw)
                try:
                    rel = _safe_relative(record.relative_path).as_posix()
                    info = archive.getinfo(rel)
                    if info.file_size != record.size:
                        raise ValueError("Package size mismatch")
                    content = archive.read(info)
                    if hashlib.sha256(content).hexdigest() != record.sha256:
                        raise ValueError("Package hash mismatch")
                    dest = _inside(destination_root, rel)
                    if dest.exists():
                        if dest.is_file() and dest.stat().st_size == record.size and sha256_file(dest) == record.sha256:
                            results.append(PreviewItem(rel, "identical", "Destination already matches"))
                        else:
                            results.append(PreviewItem(rel, "conflict", "Destination exists with different data"))
                    else:
                        results.append(PreviewItem(rel, "create", "Ready to restore"))
                except (KeyError, OSError, ValueError) as exc:
                    results.append(PreviewItem(str(raw.get("relative_path", "")), "error", str(exc)))
    return results


def restore_package(package_file: Path, passphrase: str, destination_root: Path,
                    approved_overwrites: set[str] | None = None) -> list[PreviewItem]:
    """Restore verified files. Conflicts are skipped unless their relative paths are approved."""
    approved_overwrites = approved_overwrites or set()
    plaintext, _ = _decrypt_package(package_file, passphrase)
    destination_root = destination_root.resolve(strict=True)
    outcomes: list[PreviewItem] = []
    with tempfile.TemporaryDirectory(prefix="pixelit-restore-") as tmp:
        archive_path = Path(tmp) / "payload.zip"
        archive_path.write_bytes(plaintext)
        with zipfile.ZipFile(archive_path) as archive:
            if "manifest.json" not in archive.namelist():
                raise ValueError("Package manifest is missing")
            manifest = json.loads(archive.read("manifest.json"))
            for raw in manifest.get("records", []):
                record = FileRecord(**raw)
                rel = _safe_relative(record.relative_path).as_posix()
                try:
                    info = archive.getinfo(rel)
                    data = archive.read(info)
                    if len(data) != record.size or hashlib.sha256(data).hexdigest() != record.sha256:
                        raise ValueError("Integrity check failed")
                    dest = _inside(destination_root, rel)
                    if dest.exists():
                        if dest.is_file() and dest.stat().st_size == record.size and sha256_file(dest) == record.sha256:
                            outcomes.append(PreviewItem(rel, "identical", "No change required"))
                            continue
                        if rel not in approved_overwrites:
                            outcomes.append(PreviewItem(rel, "conflict", "Skipped; overwrite not approved"))
                            continue
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    # Re-check after creating parent directories.
                    dest = _inside(destination_root, rel)
                    fd, temp_name = tempfile.mkstemp(prefix=".pixelit-restore-", dir=dest.parent)
                    temp = Path(temp_name)
                    try:
                        with os.fdopen(fd, "wb") as handle:
                            handle.write(data)
                            handle.flush()
                            os.fsync(handle.fileno())
                        if sha256_file(temp) != record.sha256:
                            raise IOError("Post-write hash mismatch")
                        if dest.exists() and rel not in approved_overwrites:
                            outcomes.append(PreviewItem(rel, "conflict", "Destination changed; skipped"))
                            continue
                        os.replace(temp, dest)
                    finally:
                        temp.unlink(missing_ok=True)
                    outcomes.append(PreviewItem(rel, "restored", "Hash verified"))
                except (KeyError, OSError, ValueError) as exc:
                    outcomes.append(PreviewItem(rel, "error", str(exc)))
    return outcomes
