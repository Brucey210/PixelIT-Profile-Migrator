"""Machine-readable technician reports that exclude passphrases and file contents."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def write_job_report(path: Path, *, job_id: str, operation: str,
                     source_label: str = "", destination_label: str = "",
                     discovered: int = 0, created: list[str] | None = None,
                     overwritten: list[str] | None = None, skipped: list[dict[str, Any]] | None = None,
                     errors: list[dict[str, Any]] | None = None,
                     verification: str = "not-run") -> Path:
    """Write a JSON audit report; callers must not pass secrets in labels/errors."""
    payload = {
        "schema_version": 1,
        "product": "Pixel IT Profile Migrator",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "job_id": job_id,
        "operation": operation,
        "source_label": source_label,
        "destination_label": destination_label,
        "files_discovered": int(discovered),
        "files_created": list(created or []),
        "files_overwritten": list(overwritten or []),
        "files_skipped": list(skipped or []),
        "errors": list(errors or []),
        "verification": verification,
        "notice": "Alpha report. Review errors and independently verify customer data before sign-off.",
    }
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".partial")
    try:
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return path


def write_credential_checklist_report(
    path: Path, *, job_id: str, items: list[dict[str, Any]]
) -> Path:
    """Persist credential-workflow status without collecting credential values."""
    payload = {
        "schema_version": 1,
        "product": "Pixel IT Profile Migrator",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "job_id": job_id,
        "operation": "credential-checklist",
        "checklist": [
            {
                "key": str(item["key"]),
                "title": str(item["title"]),
                "status": "complete" if bool(item["complete"]) else "outstanding",
                "instructions": str(item["instructions"]),
                "requires_customer_authorisation": bool(item["requires_customer_authorisation"]),
            }
            for item in items
        ],
        "notice": "Checklist status is technician-attested and does not prove successful credential transfer. No passwords, tokens, private keys or recovery keys are collected.",
    }
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".partial")
    try:
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return path
