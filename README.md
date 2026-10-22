# Pixel IT Profile Migrator

Portable Windows profile backup utility for Pixel IT technicians.

> **Status: alpha / engineering prototype. Not approved as the sole backup or for unsupervised live customer use.** Test restores and retain an independent backup.

## Current workflow

1. Choose a drive (for example, `C:\\`) and automatically discover user profiles in its `Users` folder.
2. Select one or more profiles; there is no need to browse manually to each profile path.
3. Optionally add other folders or individual files.
4. Choose either a regular directory-tree backup or a standard ZIP archive.
5. Start the backup directly. The interface shows a percentage, bytes copied in readable units, the current file, and an approximate time remaining.

The ZIP output uses the standard ZIP format and is stored without compression. The folder option creates a timestamped folder containing ordinary files and directories. Neither format requires a password or a proprietary package reader.

## Included behaviour

- Profile discovery for Windows drives, excluding common system/default profile folders.
- Optional extra file and folder selection.
- Background backup worker so the interface stays responsive.
- Streaming copies in bounded-size chunks, byte-based progress, and a live ETA estimate.
- ZIP64 support for large standard ZIP archives.
- Avoids following symbolic links and Windows reparse points.
- Prevents selecting a backup destination inside the selected source tree.
- Preserves source files; it does not delete or alter source data.

## Development

Python 3.11+:

```powershell
py -3.11 -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
python -m pip install -e ".[test]"
python -m pixelit_migrator.app
python -m pytest -v
```

See [BUILD_WINDOWS.md](BUILD_WINDOWS.md) for the portable Windows build workflow.

## Current limitations

- The utility backs up file contents and basic file timestamps; it is not a full Windows image or forensic copy.
- Windows ACLs, ownership, EFS semantics, alternate data streams, registry state, and application-specific migration are not preserved.
- Locked, cloud-placeholder, inaccessible, or changing files may prevent a complete backup; verify the final result and test opening/restoring the output.
- The ETA is an estimate based on bytes copied so far and can change substantially with many small files or slower drives.
- No code-signed release or independent security audit yet.
- Profile discovery is based on the conventional `<drive>\\Users` directory.

## Safety principles

1. Never delete the source profile as part of a backup.
2. Do not treat a successful copy as verified until the backup has been checked and a restore test completed.
3. Keep a separate backup copy for important customer data.
4. Never commit customer data, backup archives, secrets, credentials, or private keys to this repository.
