import hashlib
import pytest
from pixelit_migrator.manifest import FileRecord, MigrationManifest, resolve_under, validate_relative_path

@pytest.mark.parametrize("value", ["../x", "a/../../x", r"C:\\Windows\\x", "/tmp/x", "a//b", "a/./b"])
def test_reject_unsafe_paths(value):
    with pytest.raises(ValueError):
        validate_relative_path(value)

def test_manifest_round_trip():
    record = FileRecord("Documents/note.txt", 3, hashlib.sha256(b"abc").hexdigest())
    original = MigrationManifest("JOB1", "2026-01-01T00:00:00+00:00", "PC1", (record,))
    loaded = MigrationManifest.from_bytes(original.to_bytes())
    assert loaded == original

def test_manifest_rejects_duplicate_paths_case_insensitive():
    data = b'{"version":1,"job_id":"x","created_utc":"t","source_computer":"p","records":[' \
           b'{"path":"A.txt","size":0,"sha256":"' + b'0'*64 + b'"},' \
           b'{"path":"a.txt","size":0,"sha256":"' + b'0'*64 + b'"}]}'
    with pytest.raises(ValueError):
        MigrationManifest.from_bytes(data)

def test_resolve_rejects_symlink(tmp_path):
    root = tmp_path / "root"; root.mkdir()
    outside = tmp_path / "outside"; outside.mkdir()
    link = root / "link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Symlink creation unavailable")
    with pytest.raises(ValueError):
        resolve_under(root, "link/escape.txt")
