import hashlib
import json

import pytest

from pixelit_migrator.manifest import FileRecord, MigrationManifest, validate_relative_path


def _record(path: str, size: int = 0) -> dict:
    return {"path": path, "size": size, "sha256": hashlib.sha256(b"").hexdigest()}


@pytest.mark.parametrize(
    "path",
    ["", "../secret.txt", "folder/../../secret.txt", r"C:\\Windows\\win.ini",
     r"\\server\\share\\file", "/etc/passwd", "folder//file", "folder/./file", "a:b",
     "CON", "folder/NUL.txt", "name.", "trailing ", "bad?.txt", "bad|name.txt"],
)
def test_rejects_unsafe_relative_paths(path):
    with pytest.raises(ValueError):
        validate_relative_path(path)


def test_manifest_rejects_case_insensitive_duplicate_paths():
    data = {
        "version": 1, "job_id": "job", "created_utc": "now", "source_computer": "PC",
        "records": [_record("Documents/Note.txt"), _record("documents/note.TXT")],
    }
    with pytest.raises(ValueError, match="Duplicate"):
        MigrationManifest.from_bytes(json.dumps(data).encode())


def test_manifest_rejects_file_directory_collision():
    data = {
        "version": 1, "job_id": "job", "created_utc": "now", "source_computer": "PC",
        "records": [_record("profile"), _record("profile/settings.json")],
    }
    with pytest.raises(ValueError, match="conflicting"):
        MigrationManifest.from_bytes(json.dumps(data).encode())


@pytest.mark.parametrize("size", [-1, True, 1.5, "4"])
def test_file_record_rejects_non_integer_or_negative_sizes(size):
    record = FileRecord("note.txt", size, hashlib.sha256(b"").hexdigest())
    with pytest.raises(ValueError):
        record.validate()


def test_manifest_round_trip():
    manifest = MigrationManifest(
        "job-1", "2026-10-21T00:00:00+00:00", "TECH-PC",
        (FileRecord("Documents/note.txt", 0, hashlib.sha256(b"").hexdigest()),),
    )
    assert MigrationManifest.from_bytes(manifest.to_bytes()) == manifest


def test_manifest_rejects_oversized_input():
    with pytest.raises(ValueError, match="64 MiB"):
        MigrationManifest.from_bytes(b" " * (64 * 1024 * 1024 + 1))
