import json
from pathlib import Path
from pixelit_migrator.reporting import write_job_report


def test_report_is_written_without_secret_fields(tmp_path: Path):
    target = tmp_path / "job.json"
    write_job_report(target, job_id="JOB1", operation="restore", discovered=2,
                     created=["Documents/a.txt"], verification="sha256-passed")
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["files_created"] == ["Documents/a.txt"]
    assert "passphrase" not in payload
    assert payload["schema_version"] == 1
