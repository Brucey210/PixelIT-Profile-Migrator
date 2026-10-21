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


def test_credential_checklist_report_records_status_without_secret_values(tmp_path: Path):
    from pixelit_migrator.reporting import write_credential_checklist_report

    target = tmp_path / "credentials.json"
    write_credential_checklist_report(
        target,
        job_id="JOB-CRED",
        items=[
            {
                "key": "m365",
                "title": "Microsoft 365",
                "instructions": "Sign in again and complete MFA.",
                "requires_customer_authorisation": True,
                "complete": True,
            },
            {
                "key": "wifi",
                "title": "Wi-Fi",
                "instructions": "Use approved Windows workflow.",
                "requires_customer_authorisation": True,
                "complete": False,
            },
        ],
    )
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["operation"] == "credential-checklist"
    assert [item["status"] for item in payload["checklist"]] == ["complete", "outstanding"]
    checklist_fields = {key.casefold() for item in payload["checklist"] for key in item}
    assert not ({"password", "token", "private_key", "credential_value"} & checklist_fields)
