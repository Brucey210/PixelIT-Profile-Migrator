from pathlib import Path

from pixelit_migrator.inventory import build_manifest, discover_outlook, outlook_relative_paths


def _write(root: Path, relative: str, content: bytes = b"test") -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def test_outlook_discovery_finds_pst_signatures_and_templates(tmp_path: Path):
    profile = tmp_path / "profile"
    _write(profile, "Documents/Outlook Files/archive.pst")
    _write(profile, "AppData/Local/Microsoft/Outlook/local.pst")
    _write(profile, "AppData/Local/Microsoft/Outlook/cache.ost")
    _write(profile, "AppData/Roaming/Microsoft/Signatures/Signature.htm")
    _write(profile, "AppData/Roaming/Microsoft/Templates/Normal.dotm")

    found = discover_outlook(profile)
    assert len(found["pst"]) == 2
    assert any(path.endswith("archive.pst") for path in found["pst"])
    assert any(path.endswith("local.pst") for path in found["pst"])
    assert any(path.endswith("Signature.htm") for path in found["signatures"])
    assert any(path.endswith("Normal.dotm") for path in found["templates"])
    assert not any(path.endswith(".ost") for path in found["pst"])


def test_outlook_paths_are_relative_and_can_be_added_to_package_manifest(tmp_path: Path):
    profile = tmp_path / "profile"
    _write(profile, "Documents/Outlook Files/archive.pst", b"pst data")
    _write(profile, "AppData/Roaming/Microsoft/Signatures/Signature.htm", b"signature")
    _write(profile, "AppData/Roaming/Microsoft/Templates/Normal.dotm", b"template")

    paths = outlook_relative_paths(profile)
    assert paths == sorted(paths, key=str.casefold)
    assert all(not Path(path).is_absolute() for path in paths)
    assert "Documents/Outlook Files/archive.pst" in paths

    manifest = build_manifest(profile, paths, "OUTLOOK-1")
    assert {record.path for record in manifest.records} == set(paths)


def test_manifest_creation_fails_instead_of_silently_omitting_unreadable_file(tmp_path: Path, monkeypatch):
    from pixelit_migrator.manifest import FileRecord
    import pytest

    profile = tmp_path / "profile"
    _write(profile, "Documents/important.txt", b"important")

    def fail_inventory(cls, root, file_path):
        raise OSError("simulated read failure")

    monkeypatch.setattr(FileRecord, "from_file", classmethod(fail_inventory))
    with pytest.raises(ValueError, match="Unable to inventory selected file"):
        build_manifest(profile, ["Documents"], "INVENTORY-ERROR")
