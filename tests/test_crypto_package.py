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
