from pathlib import Path
from pixelit_migrator.preflight import run_preflight


def test_preflight_counts_files_without_modifying_source(tmp_path: Path):
    source = tmp_path / "source"; source.mkdir()
    (source / "data.txt").write_text("hello", encoding="utf-8")
    before = sorted(p.relative_to(source).as_posix() for p in source.rglob("*"))
    result = run_preflight(source)
    after = sorted(p.relative_to(source).as_posix() for p in source.rglob("*"))
    assert result["files_readable"] == 1
    assert result["bytes_readable"] == 5
    assert before == after


def test_preflight_reports_missing_package_destination(tmp_path: Path):
    source = tmp_path / "source"; source.mkdir()
    result = run_preflight(source, tmp_path / "missing" / "package.pitpkg")
    assert result["ready"] is False
    assert any(item["code"] == "TARGET_UNAVAILABLE" for item in result["findings"])
    assert not (tmp_path / "missing").exists()


def test_preflight_capacity_estimate_is_scoped_to_selected_paths(tmp_path: Path):
    source = tmp_path / "profile"
    documents = source / "Documents"
    documents.mkdir(parents=True)
    (documents / "note.txt").write_bytes(b"abc")
    unrelated = source / "AppData" / "Local"
    unrelated.mkdir(parents=True)
    (unrelated / "large-cache.bin").write_bytes(b"x" * 100_000)

    result = run_preflight(source, selected_paths=["Documents"])
    assert result["files_readable"] == 1
    assert result["bytes_readable"] == 3
    assert not any("large-cache.bin" in item["path"] for item in result["findings"])
