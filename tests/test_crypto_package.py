import hashlib
from pathlib import Path

import pytest
from pixelit_migrator.crypto_package import create_package, inspect_package, restore_package
from pixelit_migrator.manifest import FileRecord, MigrationManifest


def test_encrypted_package_round_trip_and_conflict_protection(tmp_path: Path):
    source = tmp_path / "source"; source.mkdir()
    destination = tmp_path / "destination"; destination.mkdir()
    content = b"customer test data"
    (source / "Documents").mkdir()
    (source / "Documents" / "note.txt").write_bytes(content)
    record = FileRecord("Documents/note.txt", len(content), hashlib.sha256(content).hexdigest())
    manifest = MigrationManifest("TEST-1", "2026-01-01T00:00:00+00:00", "TEST-PC", (record,))
    package = tmp_path / "backup.pitpkg"
    create_package(source, package, manifest, "long test passphrase 123")
    assert inspect_package(package, "long test passphrase 123") == manifest
    with pytest.raises(Exception):
        inspect_package(package, "incorrect passphrase")
    report = restore_package(package, destination, "long test passphrase 123")
    assert report["created"] == ["Documents/note.txt"]
    assert (destination / "Documents" / "note.txt").read_bytes() == content


def test_existing_destination_is_skipped(tmp_path: Path):
    source = tmp_path / "source"; source.mkdir()
    destination = tmp_path / "destination"; destination.mkdir()
    content = b"source"
    (source / "file.txt").write_bytes(content)
    (destination / "file.txt").write_bytes(b"keep me")
    record = FileRecord("file.txt", len(content), hashlib.sha256(content).hexdigest())
    manifest = MigrationManifest("TEST-2", "2026-01-01T00:00:00+00:00", "TEST-PC", (record,))
    package = tmp_path / "backup.pitpkg"
    create_package(source, package, manifest, "long test passphrase 123")
    report = restore_package(package, destination, "long test passphrase 123")
    assert report["skipped"][0]["path"] == "file.txt"
    assert (destination / "file.txt").read_bytes() == b"keep me"


def test_package_authentication_rejects_modified_ciphertext(tmp_path: Path):
    import zipfile

    source = tmp_path / "source"; source.mkdir()
    (source / "note.txt").write_bytes(b"authenticated payload")
    payload = b"authenticated payload"
    record = FileRecord("note.txt", len(payload), hashlib.sha256(payload).hexdigest())
    manifest = MigrationManifest("TAMPER-1", "2026-01-01T00:00:00+00:00", "TEST-PC", (record,))
    package = tmp_path / "original.pitpkg"
    create_package(source, package, manifest, "long test passphrase 123")

    tampered = tmp_path / "tampered.pitpkg"
    with zipfile.ZipFile(package, "r") as original, zipfile.ZipFile(tampered, "w") as changed:
        for info in original.infolist():
            data = original.read(info.filename)
            if info.filename == "files/note.txt":
                data = data[:-1] + bytes([data[-1] ^ 1])
            changed.writestr(info.filename, data)

    with pytest.raises(Exception):
        inspect_package(tampered, "long test passphrase 123")


def test_failed_package_creation_does_not_replace_existing_output(tmp_path: Path):
    source = tmp_path / "source"; source.mkdir()
    (source / "note.txt").write_bytes(b"changed")
    record = FileRecord("note.txt", 8, hashlib.sha256(b"original").hexdigest())
    manifest = MigrationManifest("CHANGED-1", "2026-01-01T00:00:00+00:00", "TEST-PC", (record,))
    package = tmp_path / "existing.pitpkg"
    package.write_bytes(b"existing known-good output")

    with pytest.raises(ValueError, match="Source changed"):
        create_package(source, package, manifest, "long test passphrase 123")

    assert package.read_bytes() == b"existing known-good output"
    assert not package.with_name(package.name + ".partial").exists()


@pytest.mark.parametrize("size", [0, 1, 1024 * 1024, 1024 * 1024 + 37, 2 * 1024 * 1024 + 19])
def test_streaming_package_round_trip_across_chunk_boundaries(tmp_path: Path, size: int):
    source = tmp_path / "source"; source.mkdir()
    destination = tmp_path / "destination"; destination.mkdir()
    # Deterministic content makes the expected digest reproducible without fixtures.
    content = bytes((i * 31 + 7) % 256 for i in range(size))
    (source / "large.bin").write_bytes(content)
    record = FileRecord("large.bin", size, hashlib.sha256(content).hexdigest())
    manifest = MigrationManifest("STREAM-1", "2026-01-01T00:00:00+00:00", "TEST-PC", (record,))
    package = tmp_path / "streamed.pitpkg"

    create_package(source, package, manifest, "long test passphrase 123")
    assert inspect_package(package, "long test passphrase 123") == manifest
    report = restore_package(package, destination, "long test passphrase 123")

    assert report["created"] == ["large.bin"]
    assert report["errors"] == []
    assert (destination / "large.bin").read_bytes() == content


def test_package_rejects_non_object_header_before_key_derivation(tmp_path: Path):
    import zipfile
    from pixelit_migrator.crypto_package import MAGIC

    package = tmp_path / "malformed.pitpkg"
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("header.json", MAGIC + b"[]")
        archive.writestr("manifest.bin", b"not-a-manifest")
    with pytest.raises(ValueError, match="Invalid package header"):
        inspect_package(package, "long test passphrase 123")


def test_unique_nonce_prefix_retries_collisions(monkeypatch):
    import pixelit_migrator.crypto_package as crypto

    values = [b"p" * 8, b"p" * 8, b"m" * 8, b"q" * 8]
    monkeypatch.setattr(crypto.os, "urandom", lambda length: values.pop(0))
    used = set()

    first = crypto._unique_nonce_prefix(used, b"m" * 8)
    second = crypto._unique_nonce_prefix(used, b"m" * 8)

    assert first == b"p" * 8
    assert second == b"q" * 8
    assert used == {b"p" * 8, b"q" * 8}


