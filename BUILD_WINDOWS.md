# Windows build and release notes

## Development launch

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[test]"
python -m pixelit_migrator.app
python -m pytest -v
```

## Portable build (development only)

```powershell
python -m pip install pyinstaller
pyinstaller --noconfirm --clean --windowed --name PixelIT-Profile-Migrator --collect-all cryptography --paths src main.py
```

The GitHub Actions build checks that the executable exists and includes `SHA256SUMS.txt` for the packaged files. Distribute the generated `dist/PixelIT-Profile-Migrator/` folder only after testing it on clean Windows 10/11 machines and verifying the checksums. Keep the executable unsigned until the signing and release process is defined; do not treat a successful build as validation.

## Release gate — not yet satisfied

- Run automated tests on Windows 10 and Windows 11.
- Test interrupted package creation and restore, low disk space, locked files, Unicode and long paths.
- Add Windows reparse-point detection, ACL/owner preservation decisions, EFS handling, alternate data streams, and robust rollback.
- Test Outlook versions and PSTs; confirm OST/cache handling and document data not migrated.
- Validate bounded-memory chunked encryption and restore with large PST/profile files and low-memory Windows systems. Alpha package format changed for chunking; recreate packages with the same current build.
- Add independent package signature or authenticated metadata validation, secret-handling review and dependency audit.
- Produce signed installer/portable release and checksums.

Do not use this alpha build as the only backup of customer data.
