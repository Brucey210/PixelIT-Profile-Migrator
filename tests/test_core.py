import hashlib
from pathlib import Path

import pytest

from pixelit_migrator.core import (
    create_encrypted_package, preview_package, restore_package, inventory
)


def test_inventory_and_roundtrip(tmp_path: Path):
    src = tmp_path / "src"; dst = tmp_path / "dst"
    src.mkdir(); dst.mkdir()
    (src / "docs").mkdir()
    (src / "docs" / "hello.txt").write_text("hello pixel it", encoding="utf-8")
    package = tmp_path / "migration.pitm"
    create_encrypted_package(src, package, "test-passphrase-long")
    preview = preview_package(package, "test-passphrase-long", dst)
    assert len(preview) == 1 and preview[0].status == "create"
    result = restore_package(package, "test-passphrase-long", dst)
    assert result[0].status == "restored"
    assert (dst / "docs" / "hello.txt").read_text(encoding="utf-8") == "hello pixel it"


def test_wrong_password_fails(tmp_path: Path):
    src = tmp_path / "src"; dst = tmp_path / "dst"
    src.mkdir(); dst.mkdir()
    (src / "a.txt").write_text("data", encoding="utf-8")
    package = tmp_path / "x.pitm"
    create_encrypted_package(src, package, "correct-horse-battery")
    with pytest.raises(Exception):
        preview_package(package, "wrong-password", dst)


def test_conflict_is_not_overwritten(tmp_path: Path):
    src = tmp_path / "src"; dst = tmp_path / "dst"
    src.mkdir(); dst.mkdir()
    (src / "a.txt").write_text("source", encoding="utf-8")
    (dst / "a.txt").write_text("customer data", encoding="utf-8")
    package = tmp_path / "x.pitm"
    create_encrypted_package(src, package, "correct-horse-battery")
    preview = preview_package(package, "correct-horse-battery", dst)
    assert preview[0].status == "conflict"
    result = restore_package(package, "correct-horse-battery", dst)
    assert result[0].status == "conflict"
    assert (dst / "a.txt").read_text(encoding="utf-8") == "customer data"


def test_tampered_package_fails_authentication(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("data", encoding="utf-8")
    package = tmp_path / "x.pitm"
    create_encrypted_package(src, package, "correct-horse-battery")
    raw = bytearray(package.read_bytes())
    raw[-1] ^= 0x01
    package.write_bytes(raw)
    with pytest.raises(Exception):
        preview_package(package, "correct-horse-battery", src)


def test_symlink_not_inventoried(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    outside = tmp_path / "secret.txt"
    outside.write_text("secret", encoding="utf-8")
    try:
        (src / "link.txt").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks unavailable in this environment")
    assert inventory(src) == []
