"""Read-only profile inventory and Outlook data discovery."""
from __future__ import annotations

import os
import socket
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .manifest import FileRecord, MigrationManifest, is_link_or_reparse, resolve_under, validate_relative_path

USER_FOLDERS = ("Desktop", "Documents", "Downloads", "Pictures", "Videos", "Music", "Favorites")


def _iter_regular_files(root: Path, *, strict: bool = False):
    """Walk without descending through links; strict mode fails on inaccessible folders."""
    root = root.resolve(strict=True)

    def raise_walk_error(error: OSError) -> None:
        raise error

    for current, dirs, names in os.walk(
        root, followlinks=False, onerror=raise_walk_error if strict else None
    ):
        base = Path(current)
        dirs[:] = [name for name in dirs if not is_link_or_reparse(base / name)]
        for name in names:
            path = base / name
            if is_link_or_reparse(path) or not path.is_file():
                continue
            yield path


def list_profiles() -> list[Path]:
    """List conventional local profiles on Windows; caller chooses the source."""
    if os.name != "nt":
        return []
    root = Path(os.environ.get("SystemDrive", "C:") + "\\Users")
    excluded = {"Public", "Default", "Default User", "All Users"}
    if not root.exists():
        return []
    return sorted((p for p in root.iterdir() if p.is_dir() and not is_link_or_reparse(p) and p.name not in excluded), key=lambda p: p.name.casefold())


def discover_outlook(profile: Path) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {"pst": [], "signatures": [], "templates": [], "notes": []}
    appdata = profile / "AppData" / "Roaming" / "Microsoft"
    for base in (profile / "Documents" / "Outlook Files", profile / "AppData" / "Local" / "Microsoft" / "Outlook"):
        if base.is_dir() and not is_link_or_reparse(base):
            found["pst"].extend(str(p) for p in _iter_regular_files(base) if p.suffix.casefold() == ".pst")
    for key, path in (("signatures", appdata / "Signatures"), ("templates", appdata / "Templates")):
        if path.is_dir() and not is_link_or_reparse(path):
            found[key].extend(str(p) for p in _iter_regular_files(path))
    found["notes"].extend([
        "OST files are normally cache files and should be rebuilt by Outlook; do not rely on OST as the only mailbox copy.",
        "Modern Outlook accounts may require sign-in and profile recreation on the destination.",
        "Outlook rules, autocomplete, local contacts/calendars and account settings vary by Outlook version and account type; verify separately.",
    ])
    return found


def build_manifest(source_root: Path, selected_paths: list[str], job_id: str | None = None) -> MigrationManifest:
    root = source_root.resolve(strict=True)
    records: list[FileRecord] = []
    seen: set[str] = set()
    for raw_relative in selected_paths:
        relative = validate_relative_path(raw_relative)
        path = resolve_under(root, relative)
        if is_link_or_reparse(path):
            continue
        candidates = [path] if path.is_file() else _iter_regular_files(path, strict=True) if path.is_dir() else []
        for child in candidates:
            try:
                record = FileRecord.from_file(root, child)
            except (OSError, ValueError) as exc:
                # Never silently omit a file from a migration manifest: abort so the
                # technician can correct the source or scope and retry.
                raise ValueError(f"Unable to inventory selected file {child}: {exc}") from exc
            folded = record.path.casefold()
            if folded not in seen:
                records.append(record)
                seen.add(folded)
    records.sort(key=lambda item: item.path.casefold())
    return MigrationManifest(job_id=job_id or uuid4().hex[:12].upper(),
                             created_utc=datetime.now(timezone.utc).isoformat(),
                             source_computer=socket.gethostname(), records=tuple(records))


def outlook_relative_paths(profile: Path) -> list[str]:
    """Return discovered Outlook payload paths relative to the chosen profile root."""
    root = profile.resolve(strict=True)
    found = discover_outlook(root)
    paths: dict[str, str] = {}
    for category in ("pst", "signatures", "templates"):
        for value in found[category]:
            try:
                candidate = Path(value).resolve(strict=True)
                relative = candidate.relative_to(root).as_posix()
                validate_relative_path(relative)
                if is_link_or_reparse(candidate) or not candidate.is_file():
                    continue
                paths.setdefault(relative.casefold(), relative)
            except (OSError, ValueError):
                # Files can be moved/removed while inventory is running.
                continue
    return sorted(paths.values(), key=str.casefold)
