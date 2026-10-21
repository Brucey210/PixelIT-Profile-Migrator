"""Authenticated encrypted package format (v1).

Package files are individually encrypted with AES-GCM. A random data key is
wrapped using Scrypt-derived AES-GCM key encryption. Never log passphrases.
"""
from __future__ import annotations

import json
import os
import secrets
import zipfile
from pathlib import Path
from typing import Iterable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .manifest import FileRecord, MigrationManifest, resolve_under

MAGIC = b"PIXELITPKG1\n"
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32


def _derive(passphrase: str, salt: bytes) -> bytes:
    if not passphrase or len(passphrase) < 12:
        raise ValueError("Use a passphrase of at least 12 characters")
    return Scrypt(salt=salt, length=KEY_LEN, n=2**15, r=8, p=1).derive(passphrase.encode("utf-8"))


def create_package(source_root: Path, output_path: Path, manifest: MigrationManifest,
                   passphrase: str, *, progress=None) -> None:
    """Create encrypted archive; source is read only. Output is written atomically."""
    source_root = source_root.resolve(strict=True)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    salt = os.urandom(SALT_LEN)
    wrap_nonce = os.urandom(NONCE_LEN)
    data_key = AESGCM.generate_key(bit_length=256)
    wrapping_key = _derive(passphrase, salt)
    wrapped_key = AESGCM(wrapping_key).encrypt(wrap_nonce, data_key, MAGIC)
    header = json.dumps({"v": 1, "salt": salt.hex(), "wrap_nonce": wrap_nonce.hex(),
                         "wrapped_key": wrapped_key.hex()}, sort_keys=True).encode("utf-8")
    temp = output_path.with_name(output_path.name + ".partial")
    try:
        with zipfile.ZipFile(temp, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
            archive.writestr("header.json", MAGIC + header)
            manifest_nonce = os.urandom(NONCE_LEN)
            encrypted_manifest = AESGCM(data_key).encrypt(manifest_nonce, manifest.to_bytes(), b"manifest-v1")
            archive.writestr("manifest.bin", manifest_nonce + encrypted_manifest)
            aes = AESGCM(data_key)
            total = len(manifest.records)
            for index, record in enumerate(manifest.records, start=1):
                source = resolve_under(source_root, record.path)
                if not source.is_file() or source.stat().st_size != record.size:
                    raise ValueError(f"Source changed since inventory: {record.path}")
                nonce = os.urandom(NONCE_LEN)
                with source.open("rb") as stream:
                    content = stream.read()
                import hashlib
                if hashlib.sha256(content).hexdigest() != record.sha256:
                    raise ValueError(f"Source changed since inventory: {record.path}")
                encrypted = nonce + aes.encrypt(nonce, content, record.path.encode("utf-8"))
                archive.writestr("files/" + record.path, encrypted)
                if progress:
                    progress(index, total, record.path)
        os.replace(temp, output_path)
    finally:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
        # Best-effort reference clearing; Python cannot guarantee memory erasure.
        data_key = b"\x00" * len(data_key)


def _unlock(archive: zipfile.ZipFile, passphrase: str) -> tuple[bytes, MigrationManifest]:
    names = archive.namelist()
    if len(names) != len(set(names)):
        raise ValueError("Archive contains duplicate entry names")
    raw_header = archive.read("header.json")
    if not raw_header.startswith(MAGIC):
        raise ValueError("Not a Pixel IT package")
    header = json.loads(raw_header[len(MAGIC):].decode("utf-8"))
    if header.get("v") != 1:
        raise ValueError("Unsupported package version")
    salt, nonce = bytes.fromhex(header["salt"]), bytes.fromhex(header["wrap_nonce"])
    wrapping_key = _derive(passphrase, salt)
    data_key = AESGCM(wrapping_key).decrypt(nonce, bytes.fromhex(header["wrapped_key"]), MAGIC)
    raw_manifest = archive.read("manifest.bin")
    if len(raw_manifest) < NONCE_LEN + 16:
        raise ValueError("Truncated manifest")
    manifest = AESGCM(data_key).decrypt(raw_manifest[:NONCE_LEN], raw_manifest[NONCE_LEN:], b"manifest-v1")
    return data_key, MigrationManifest.from_bytes(manifest)


def inspect_package(package_path: Path, passphrase: str) -> MigrationManifest:
    with zipfile.ZipFile(package_path, "r") as archive:
        _, manifest = _unlock(archive, passphrase)
        expected = {"header.json", "manifest.bin"}
        expected.update("files/" + r.path for r in manifest.records)
        if set(archive.namelist()) != expected:
            raise ValueError("Package entries do not match authenticated manifest")
        return manifest


def restore_package(package_path: Path, destination_root: Path, passphrase: str,
                    *, overwrite_paths: set[str] | None = None, progress=None) -> dict:
    """Restore with conflict protection and per-file authenticated verification.

    overwrite_paths contains exact relative paths the operator explicitly approved.
    A conflict without approval is skipped. Destination files are staged beside the
    target and atomically replaced only after authentication and hash verification.
    """
    overwrite_paths = {p.replace("\\", "/") for p in (overwrite_paths or set())}
    destination_root = destination_root.resolve(strict=True)
    report = {"created": [], "overwritten": [], "skipped": [], "errors": []}
    with zipfile.ZipFile(package_path, "r") as archive:
        data_key, manifest = _unlock(archive, passphrase)
        expected = {"header.json", "manifest.bin"}
        expected.update("files/" + r.path for r in manifest.records)
        if set(archive.namelist()) != expected:
            raise ValueError("Package entries do not match authenticated manifest")
        aes = AESGCM(data_key)
        for index, record in enumerate(manifest.records, start=1):
            try:
                target = resolve_under(destination_root, record.path)
                if target.exists() and record.path not in overwrite_paths:
                    report["skipped"].append({"path": record.path, "reason": "Destination exists; overwrite not approved"})
                    continue
                encrypted = archive.read("files/" + record.path)
                if len(encrypted) < NONCE_LEN + 16:
                    raise ValueError("Encrypted file entry is truncated")
                content = aes.decrypt(encrypted[:NONCE_LEN], encrypted[NONCE_LEN:], record.path.encode("utf-8"))
                import hashlib
                if len(content) != record.size or hashlib.sha256(content).hexdigest() != record.sha256:
                    raise ValueError("Decrypted file integrity check failed")
                target.parent.mkdir(parents=True, exist_ok=True)
                # Re-check destination after parent creation; reparse-point-safe
                # Windows implementation is required before production release.
                target = resolve_under(destination_root, record.path)
                if target.exists() and record.path not in overwrite_paths:
                    report["skipped"].append({"path": record.path, "reason": "Destination appeared during restore"})
                    continue
                temporary = target.with_name(target.name + ".pixelit-partial")
                try:
                    with temporary.open("xb") as stream:
                        stream.write(content)
                        stream.flush()
                        os.fsync(stream.fileno())
                    if hashlib.sha256(temporary.read_bytes()).hexdigest() != record.sha256:
                        raise IOError("Written file verification failed")
                    was_existing = target.exists()
                    if was_existing and record.path not in overwrite_paths:
                        report["skipped"].append({"path": record.path, "reason": "Conflict appeared before replace"})
                        continue
                    os.replace(temporary, target)
                    report["overwritten" if was_existing else "created"].append(record.path)
                finally:
                    temporary.unlink(missing_ok=True)
            except Exception as exc:
                report["errors"].append({"path": record.path, "reason": str(exc)})
            if progress:
                progress(index, len(manifest.records), record.path)
    return report
