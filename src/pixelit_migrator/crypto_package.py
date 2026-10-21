"""Authenticated encrypted migration packages with bounded-memory file streaming.

Each file is encrypted in independently authenticated AES-GCM chunks. The manifest
contains whole-file sizes and SHA-256 digests, which are checked while streaming.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import zipfile
from pathlib import Path
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .manifest import MigrationManifest, resolve_under

MAGIC = b"PIXELITPKG1\n"
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
CHUNK_SIZE = 1024 * 1024
_NONCE_PREFIX_LEN = 8
_TAG_LEN = 16
_MAX_CHUNKS = 2**32


def _derive(passphrase: str, salt: bytes) -> bytes:
    if not passphrase or len(passphrase) < 12:
        raise ValueError("Use a passphrase of at least 12 characters")
    return Scrypt(salt=salt, length=KEY_LEN, n=2**15, r=8, p=1).derive(passphrase.encode("utf-8"))


def _nonce(prefix: bytes, counter: int) -> bytes:
    if len(prefix) != _NONCE_PREFIX_LEN or not 0 <= counter < _MAX_CHUNKS:
        raise ValueError("Invalid encrypted chunk counter")
    return prefix + counter.to_bytes(4, "big")


def _aad(path: str, counter: int) -> bytes:
    return path.encode("utf-8") + b"\x00pixelit-chunk-v1\x00" + counter.to_bytes(4, "big")


def _read_exact(stream: BinaryIO, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        piece = stream.read(length - len(chunks))
        if not piece:
            raise ValueError("Truncated encrypted file entry")
        chunks.extend(piece)
    return bytes(chunks)


def _encrypt_file(
    source_root: Path, record, archive: zipfile.ZipFile, aes: AESGCM, prefix: bytes
) -> None:
    source = resolve_under(source_root, record.path)
    if not source.is_file() or source.stat().st_size != record.size:
        raise ValueError(f"Source changed since inventory: {record.path}")
    digest = hashlib.sha256()
    counter = 0
    if len(prefix) != _NONCE_PREFIX_LEN:
        raise ValueError("Invalid per-file nonce prefix")
    with source.open("rb") as incoming, archive.open("files/" + record.path, "w", force_zip64=True) as outgoing:
        outgoing.write(prefix)
        while True:
            chunk = incoming.read(CHUNK_SIZE)
            if not chunk:
                break
            if counter >= _MAX_CHUNKS:
                raise ValueError(f"File too large for package format: {record.path}")
            digest.update(chunk)
            outgoing.write(aes.encrypt(_nonce(prefix, counter), chunk, _aad(record.path, counter)))
            counter += 1
        # Detect growth/shrinkage while reading, and reject any content drift.
        if digest.hexdigest() != record.sha256:
            raise ValueError(f"Source changed since inventory: {record.path}")
        if source.stat().st_size != record.size:
            raise ValueError(f"Source changed since inventory: {record.path}")


def _decrypt_file(incoming: BinaryIO, outgoing: BinaryIO | None, record, aes: AESGCM) -> str:
    prefix = _read_exact(incoming, _NONCE_PREFIX_LEN)
    digest = hashlib.sha256()
    remaining = record.size
    counter = 0
    while remaining > 0:
        if counter >= _MAX_CHUNKS:
            raise ValueError(f"Too many encrypted chunks: {record.path}")
        plain_length = min(CHUNK_SIZE, remaining)
        encrypted = _read_exact(incoming, plain_length + _TAG_LEN)
        try:
            plain = aes.decrypt(_nonce(prefix, counter), encrypted, _aad(record.path, counter))
        except InvalidTag as exc:
            raise ValueError(f"Authentication failed for file: {record.path}") from exc
        if len(plain) != plain_length:
            raise ValueError(f"Invalid decrypted chunk size: {record.path}")
        digest.update(plain)
        if outgoing is not None:
            outgoing.write(plain)
        remaining -= len(plain)
        counter += 1
    if incoming.read(1):
        raise ValueError(f"Unexpected trailing bytes in encrypted file: {record.path}")
    result = digest.hexdigest()
    if result != record.sha256:
        raise ValueError(f"File integrity verification failed: {record.path}")
    return result


def create_package(source_root: Path, output_path: Path, manifest: MigrationManifest,
                   passphrase: str, *, progress=None) -> None:
    """Create a package atomically without buffering whole profile files in memory."""
    source_root = source_root.resolve(strict=True)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    salt = os.urandom(SALT_LEN)
    wrap_nonce = os.urandom(NONCE_LEN)
    data_key = AESGCM.generate_key(bit_length=256)
    wrapping_key = _derive(passphrase, salt)
    wrapped_key = AESGCM(wrapping_key).encrypt(wrap_nonce, data_key, MAGIC)
    header = json.dumps({"v": 1, "file_format": "chunked-aesgcm-v1", "salt": salt.hex(),
                         "wrap_nonce": wrap_nonce.hex(), "wrapped_key": wrapped_key.hex()},
                        sort_keys=True).encode("utf-8")
    fd, temp_name = tempfile.mkstemp(prefix=output_path.name + ".", suffix=".partial",
                                     dir=str(output_path.parent))
    os.close(fd)
    temp = Path(temp_name)
    try:
        with zipfile.ZipFile(temp, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
            archive.writestr("header.json", MAGIC + header)
            manifest_nonce = os.urandom(NONCE_LEN)
            encrypted_manifest = AESGCM(data_key).encrypt(manifest_nonce, manifest.to_bytes(), b"manifest-v1")
            archive.writestr("manifest.bin", manifest_nonce + encrypted_manifest)
            aes = AESGCM(data_key)
            # A unique prefix per file guarantees chunk nonces do not repeat under
            # the same data key, including the separately encrypted manifest nonce.
            used_prefixes = {manifest_nonce[:_NONCE_PREFIX_LEN]}
            total = len(manifest.records)
            for index, record in enumerate(manifest.records, start=1):
                prefix = os.urandom(_NONCE_PREFIX_LEN)
                while prefix in used_prefixes:
                    prefix = os.urandom(_NONCE_PREFIX_LEN)
                used_prefixes.add(prefix)
                _encrypt_file(source_root, record, archive, aes, prefix)
                if progress:
                    progress(index, total, record.path)
        # Atomic replacement only after the complete archive has closed successfully.
        os.replace(temp, output_path)
    finally:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
        data_key = b"\x00" * len(data_key)
        wrapping_key = b"\x00" * len(wrapping_key)


def _unlock(archive: zipfile.ZipFile, passphrase: str) -> tuple[bytes, MigrationManifest]:
    infos = archive.infolist()
    names = [info.filename for info in infos]
    if len(names) != len(set(names)):
        raise ValueError("Archive contains duplicate entry names")
    if any(info.flag_bits & 0x1 for info in infos):
        raise ValueError("Unexpected ZIP-level encryption")
    info_by_name = {info.filename: info for info in infos}
    if "header.json" not in info_by_name or "manifest.bin" not in info_by_name:
        raise ValueError("Package is missing required metadata")
    if any(info.compress_type != zipfile.ZIP_STORED for info in infos):
        raise ValueError("Unsupported compressed package entry")
    if info_by_name["header.json"].file_size > 64 * 1024:
        raise ValueError("Package header exceeds the safety limit")
    if info_by_name["manifest.bin"].file_size > 64 * 1024 * 1024 + NONCE_LEN + _TAG_LEN:
        raise ValueError("Encrypted manifest exceeds the safety limit")
    raw_header = archive.read("header.json")
    if not raw_header.startswith(MAGIC):
        raise ValueError("Not a Pixel IT package")
    try:
        header = json.loads(raw_header[len(MAGIC):].decode("utf-8"))
        if not isinstance(header, dict):
            raise ValueError("Invalid package header object")
        if header.get("v") != 1 or header.get("file_format") != "chunked-aesgcm-v1":
            raise ValueError("Unsupported package/file format version")
        salt = bytes.fromhex(header["salt"])
        nonce = bytes.fromhex(header["wrap_nonce"])
        wrapped_key = bytes.fromhex(header["wrapped_key"])
        if len(salt) != SALT_LEN or len(nonce) != NONCE_LEN or len(wrapped_key) != KEY_LEN + _TAG_LEN:
            raise ValueError("Invalid package key header")
    except (KeyError, TypeError, ValueError, AttributeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid package header") from exc
    wrapping_key = _derive(passphrase, salt)
    try:
        data_key = AESGCM(wrapping_key).decrypt(nonce, wrapped_key, MAGIC)
    except InvalidTag as exc:
        raise ValueError("Incorrect passphrase or damaged package header") from exc
    raw_manifest = archive.read("manifest.bin")
    if len(raw_manifest) < NONCE_LEN + _TAG_LEN:
        raise ValueError("Truncated manifest")
    try:
        manifest_data = AESGCM(data_key).decrypt(raw_manifest[:NONCE_LEN], raw_manifest[NONCE_LEN:], b"manifest-v1")
    except InvalidTag as exc:
        raise ValueError("Manifest authentication failed") from exc
    return data_key, MigrationManifest.from_bytes(manifest_data)


def _validate_entries(archive: zipfile.ZipFile, data_key: bytes, manifest: MigrationManifest) -> None:
    expected = {"header.json", "manifest.bin"}
    expected.update("files/" + record.path for record in manifest.records)
    if set(archive.namelist()) != expected:
        raise ValueError("Package entries do not match authenticated manifest")
    aes = AESGCM(data_key)
    for record in manifest.records:
        with archive.open("files/" + record.path, "r") as incoming:
            _decrypt_file(incoming, None, record, aes)


def inspect_package(package_path: Path, passphrase: str) -> MigrationManifest:
    """Authenticate the manifest and every encrypted file before reporting valid."""
    with zipfile.ZipFile(package_path, "r") as archive:
        data_key, manifest = _unlock(archive, passphrase)
        _validate_entries(archive, data_key, manifest)
        return manifest


def restore_package(package_path: Path, destination_root: Path, passphrase: str,
                    *, overwrite_paths: set[str] | None = None, progress=None) -> dict:
    """Restore verified files using bounded-memory streams; conflicts are skipped by default."""
    overwrite_paths = {p.replace("\\", "/") for p in (overwrite_paths or set())}
    destination_root = destination_root.resolve(strict=True)
    report = {"created": [], "overwritten": [], "skipped": [], "errors": []}
    with zipfile.ZipFile(package_path, "r") as archive:
        data_key, manifest = _unlock(archive, passphrase)
        _validate_entries(archive, data_key, manifest)
        aes = AESGCM(data_key)
        for index, record in enumerate(manifest.records, start=1):
            temporary: Path | None = None
            try:
                target = resolve_under(destination_root, record.path)
                if target.exists() and record.path not in overwrite_paths:
                    report["skipped"].append({"path": record.path, "reason": "Destination exists; overwrite not approved"})
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                target = resolve_under(destination_root, record.path)
                if target.exists() and record.path not in overwrite_paths:
                    report["skipped"].append({"path": record.path, "reason": "Destination appeared during restore"})
                    continue
                fd, temp_name = tempfile.mkstemp(prefix=target.name + ".pixelit-", suffix=".partial",
                                                 dir=str(target.parent))
                temporary = Path(temp_name)
                digest = hashlib.sha256()
                with os.fdopen(fd, "wb") as outgoing, archive.open("files/" + record.path, "r") as incoming:
                    _decrypt_file(incoming, outgoing, record, aes)
                    outgoing.flush()
                    os.fsync(outgoing.fileno())
                # Re-check the completed temporary file before publishing it.
                with temporary.open("rb") as check:
                    while True:
                        chunk = check.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        digest.update(chunk)
                if digest.hexdigest() != record.sha256 or temporary.stat().st_size != record.size:
                    raise IOError("Written file verification failed")
                target = resolve_under(destination_root, record.path)
                was_existing = target.exists()
                if was_existing and record.path not in overwrite_paths:
                    report["skipped"].append({"path": record.path, "reason": "Conflict appeared before replace"})
                    continue
                os.replace(temporary, target)
                temporary = None
                report["overwritten" if was_existing else "created"].append(record.path)
            except Exception as exc:
                report["errors"].append({"path": record.path, "reason": str(exc)})
            finally:
                if temporary is not None:
                    try:
                        temporary.unlink(missing_ok=True)
                    except OSError:
                        pass
            if progress:
                progress(index, len(manifest.records), record.path)
    return report
