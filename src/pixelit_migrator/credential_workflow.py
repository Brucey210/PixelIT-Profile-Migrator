"""Safe technician checklist for credentials that cannot be migrated generically.

This module intentionally does not extract passwords, browser secret stores,
Windows Credential Manager secrets, authentication tokens, or password hashes.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ChecklistItem:
    key: str
    title: str
    instructions: str
    requires_customer_authorisation: bool = True


CREDENTIAL_CHECKLIST = (
    ChecklistItem("browser", "Browser passwords and sync", "Use the browser vendor's documented sync or export/import workflow. Protect any exported CSV as highly sensitive and securely delete it after confirmed import."),
    ChecklistItem("password_manager", "Password manager", "Use the password manager's supported export/import or account sync. Confirm the vault opens on the destination and then dispose of any temporary export securely."),
    ChecklistItem("certificates", "User certificates", "Inventory required certificates and private-key availability. Export/import only with explicit authorisation and the vendor-supported process; never include private keys in ordinary profile packages."),
    ChecklistItem("wifi", "Wi-Fi profiles", "Where authorised, use Windows-supported WLAN profile export/import. Treat exports containing key material as secrets and store them encrypted."),
    ChecklistItem("vpn", "VPN and remote access", "Record provider, profile names and configuration requirements. Reinstall the approved client and reauthenticate; do not copy tokens or private secrets."),
    ChecklistItem("m365", "Microsoft 365 and modern authentication", "Sign in again on the destination and complete MFA/Conditional Access. Do not attempt to migrate refresh tokens or session cookies."),
    ChecklistItem("bitlocker", "BitLocker recovery", "Confirm recovery-key escrow in the organisation's approved system before device changes. Never place recovery keys in ordinary migration logs."),
    ChecklistItem("windows_credential_manager", "Windows Credential Manager", "Recreate saved connections through the relevant applications. The tool does not dump or decrypt Credential Manager secrets."),
)


def checklist_as_dicts() -> list[dict[str, str | bool]]:
    return [{"key": item.key, "title": item.title, "instructions": item.instructions,
             "requires_customer_authorisation": item.requires_customer_authorisation}
            for item in CREDENTIAL_CHECKLIST]
