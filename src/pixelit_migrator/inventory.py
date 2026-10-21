"""Read-only profile inventory and Outlook data discovery."""
from __future__ import annotations

import os
import socket
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .manifest import FileRecord, MigrationManifest

USER_FOLDERS = ("Desktop", "Documents", "Downloads", "Pictures", "Videos", "Music", "Favorites")
OUTLOOK_PATHS = (
    Path("AppData/Roaming/Microsoft/Signatures"),
    Path("AppData/Roaming/Microsoft/Templates"),
    Path("Documents/Outlook Files"),
)


def list_profiles() -> list[Path]:
    """List conventional local profiles on Windows; caller chooses the source."""
    if os.name != "nt":
        return []
    root = Path(os.environ.get("SystemDrive", "C:") + "\\Users")
    excluded = {"Public", "Default", "Default User", "All Users"}
    if not root.exists():
        return []
    return sorted((p for p in root.iterdir() if p.is_dir() and p.name not in excluded), key=lambda p: p.name.casefold())


def discover_outlook(profile: Path) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {"pst": [], "signatures": [], "templates": [], "notes": []}
    appdata = profile / "AppData" / "Roaming" / "Microsoft"
    for base in (profile / "Documents" / "Outlook Files", profile / "AppData" / "Local" / "Microsoft" / "Outlook"):
        if base.exists():
            found["pst"].extend(str(p) for p in base.rglob("*.pst") if p.is_file())
    for key, path in (("signatures", appdata / "Signatures"), ("templates", appdata / "Templates")):
        if path.exists():
            found[key].extend(str(p) for p in path.rglob("*") if p.is_file())
    found["notes"].extend([
        "OST files are normally cache files and should be rebuilt by Outlook; do not rely on OST as the only mailbox copy.",
        "Modern Outlook accounts may require sign-in and profile recreation on the destination.",
        "Outlook rules, autocomplete, local contacts/calendars and account settings vary by Outlook version and account type; verify separately.",
    ])
    return found


def build_manifest(source_root: Path, selected_paths: list[str], job_id: str | None = None) -> MigrationManifest:
    root = source_root.resolve(strict=True)
    records: list[FileRecord] = []
    for relative in selected_paths:
        path = root / relative
        if path.is_symlink():
            continue
        if path.is_file():
            records.append(FileRecord.from_file(root, path))
        elif path.is_dir():
            for child in path.rglob("*"):
                if child.is_symlink() or not child.is_file():
                    continue
                try:
                    records.append(FileRecord.from_file(root, child))
                except (OSError, ValueError):
                    continue
    records.sort(key=lambda item: item.path.casefold())
    return MigrationManifest(
        job_id=job_id or uuid4().hex[:12].upper(),
        created_utc=datetime.now(timezone.utc).isoformat(),
        source_computer=socket.gethostname(),
        records=tuple(records),
    )
