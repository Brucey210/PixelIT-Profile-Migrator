# Pixel IT Profile Migrator

Portable Windows profile migration toolkit for Pixel IT technicians.

> **Status: alpha / engineering prototype. Not approved for live customer migrations.** Always retain a separate verified backup. This repository currently produces source code and a manual Windows build workflow; it is not a signed production release.

## Implemented in the current branch

- PySide6 desktop interface with package creation and restore tabs; inventory, package creation, package verification and restore run in a worker thread so large operations do not intentionally block the UI.
- Folder selection for common profile folders, optional automatic inclusion of discovered Outlook PSTs/signatures/templates, and a selected-scope preflight scan.
- Scrypt-derived AES-256-GCM key wrapping and chunked per-file AES-GCM encryption, with bounded-memory processing for large files.
- Encrypted manifest with file sizes and SHA-256 hashes; package inspection authenticates every payload.
- Restore preview, conflict skipping by default, hash verification, and atomic staging for individual files.
- Exportable credential-handling checklist report that directs technicians to vendor-supported transfer and reauthentication; no secret-store scraping or credential values stored in the report.
- JSON technician reports for package creation and restore.
- GitHub Actions tests on Windows and Ubuntu, a manual Windows portable-folder build workflow, and scheduled dependency vulnerability auditing.
- Strict manifest checks for traversal, case-insensitive duplicates, file/directory collisions, invalid Windows names, and malformed sizes.

## Development

Python 3.11+:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[test]"
python -m pixelit_migrator.app
python -m pytest -v
```

See [BUILD_WINDOWS.md](BUILD_WINDOWS.md) for the development packaging command and release gates. The Windows artifact workflow is available from **Actions → Windows portable build (alpha) → Run workflow**. A successful build does not make this software production-ready.

## Known blockers before production

- The package payload format changed during alpha to support chunked encryption; treat older alpha packages as incompatible and recreate them with the current build.
- Windows reparse-point/junction handling needs native checks and race-resistant restore writes; temporary files are staged atomically, but full transactional rollback is not implemented.
- No preservation of ACLs, owners, EFS semantics, alternate data streams, all timestamps, registry settings or application-specific state.
- No durable interrupted-job resume journal, full rollback, signed reports, or code-signed release.
- Outlook support currently discovers selected files; it does not guarantee rules, autocomplete, local contacts/calendars, account profiles or modern authentication migration.
- Credential handling is a checklist only; it does not automate certificate or Wi-Fi export/import.
- Windows 10/11 integration tests, long-path/locked-file/low-disk tests, dependency/security review and clean-machine packaging tests are still required.

## Safety principles

1. Never delete the source profile as part of migration.
2. Never silently overwrite existing destination files.
3. Authenticate package data and verify hashes before writing restored files.
4. Never log passwords, tokens, private keys or credential export contents.
5. Never use this alpha build as the only backup or describe it as production-ready.

## Repository visibility

Review the repository's GitHub visibility before adding customer-related material. Never commit migration packages, customer files, secrets, credentials, or private keys.
