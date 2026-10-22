from pathlib import Path
import zipfile

import pytest

from pixelit_migrator.backup_engine import create_backup, discover_profiles, format_bytes, inventory


def test_discovers_profiles_and_excludes_default_and_public(tmp_path):
    users = tmp_path / "Users"
    for name in ("Alice", "Bob", "Public", "Default", "Default User"):
        (users / name).mkdir(parents=True)
    found = discover_profiles(tmp_path)
    assert [p.name for p in found] == ["Alice", "Bob"]


def test_inventory_and_standard_uncompressed_zip(tmp_path):
    profile = tmp_path / "Users" / "Alice"
    (profile / "Documents").mkdir(parents=True)
    (profile / "Documents" / "notes.txt").write_text("backup data", encoding="utf-8")
    extra = tmp_path / "Company"
    extra.mkdir()
    (extra / "jobs.csv").write_text("id,name\n1,Example\n", encoding="utf-8")
    items, total = inventory([profile], [extra])
    assert len(items) == 2
    assert total == len("backup data") + len("id,name\n1,Example\n".encode())
    progress = []
    destination = tmp_path / "backup.zip"
    result = create_backup([profile], [extra], destination, "zip", lambda done, size, name: progress.append((done, size, name)))
    assert result["files"] == 2
    assert result["bytes"] == total
    assert destination.exists()
    with zipfile.ZipFile(destination) as archive:
        assert archive.getinfo("Profiles/Alice/Documents/notes.txt").compress_type == zipfile.ZIP_STORED
        assert archive.read("Profiles/Alice/Documents/notes.txt") == b"backup data"
        assert archive.read("Additional/Company/jobs.csv").startswith(b"id,name")
    assert progress and progress[-1][0] == total


def test_folder_backup_creates_regular_tree(tmp_path):
    profile = tmp_path / "Users" / "Alice"
    profile.mkdir(parents=True)
    (profile / "data.bin").write_bytes(b"12345")
    destination = tmp_path / "backups"
    destination.mkdir()
    result = create_backup([profile], [], destination, "folder")
    assert result["files"] == 1
    assert (result["output"] / "Profiles" / "Alice" / "data.bin").read_bytes() == b"12345"


def test_refuses_backup_destination_inside_source(tmp_path):
    profile = tmp_path / "Users" / "Alice"
    profile.mkdir(parents=True)
    (profile / "data.txt").write_text("hello")
    with pytest.raises(ValueError, match="outside the selected source"):
        create_backup([profile], [], profile / "backup.zip", "zip")


def test_format_bytes_uses_human_readable_units():
    assert format_bytes(0) == "0 B"
    assert format_bytes(1024 * 1024) == "1.0 MB"
    assert format_bytes(1024 ** 3) == "1.0 GB"
