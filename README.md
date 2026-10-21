# Pixel IT Profile Migrator

Portable Windows profile migration toolkit for Pixel IT technicians.

> **Development status: alpha.** This repository is not yet production-ready. Do not use it as the sole copy of customer data or on live migrations without a separate verified backup.

## First-release goals

- Preflight inventory of user profiles and common user folders.
- Encrypted migration packages with authenticated metadata and per-file SHA-256 verification.
- Preview-before-restore and explicit conflict handling.
- Outlook data discovery (PST files, signatures, templates) with clear notes on data requiring separate handling.
- Safe credential workflows: supported exports/imports, certificates and Wi-Fi configuration where authorised; no scraping of browser passwords, Windows password hashes, or authentication tokens.
- Technician logs and customer handover report.
- Portable Windows build and automated tests.

## Current implementation

This repository is being built incrementally. Features are only considered complete when integrated and covered by tests. Windows-specific behaviour (ACLs, EFS, reparse points, long paths, Outlook versions and packaging) must be tested on supported Windows versions before release.

## Development

Python 3.11+ is recommended for development. Create a virtual environment and install the project dependencies from `requirements.txt` once the initial application modules have landed.

## Safety principles

1. Source data is read-only during packaging; migration does not delete the source profile.
2. Restore must preview changes and never silently overwrite destination data.
3. Verify package authentication and file hashes before writing restored files.
4. Never log passwords, tokens, private keys, or credential export contents.
5. Do not call the software production-ready until automated tests and Windows integration tests pass.

## Licence

Private project for Pixel IT. Add the applicable licence before external distribution.
