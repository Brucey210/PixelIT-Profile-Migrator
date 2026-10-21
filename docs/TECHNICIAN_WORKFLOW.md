# Technician workflow (alpha)

1. Obtain customer authorisation, assign a job ID, and confirm an independent verified backup exists.
2. Launch the application on a development/test machine. Select the source profile root (normally the user's profile directory).
3. Select common folders to package. The tool currently includes folder trees by relative path; review scope carefully.
4. Run preflight and Outlook discovery. The preflight is advisory and cannot prove cloud placeholders are hydrated or Windows metadata will be preserved.
5. Choose an output path on approved encrypted storage and use a unique strong passphrase (12+ characters). Store the passphrase separately from the package.
6. Create the package and save the technician JSON report. Keep the source untouched.
7. Transfer the package securely to the destination PC and open the Restore tab.
8. Select an existing destination profile root and inspect the package. Inspection authenticates the manifest and all encrypted file payloads.
9. Review the preview. Existing files are skipped unless explicitly approved through the engine API; the current UI intentionally does not offer overwrites.
10. Restore to a test/destination profile, review errors/skipped files, save the report, and reopen representative files. Validate Outlook/mailbox behaviour separately.
11. Retain the source and independent backup until the customer accepts the migration and the job is signed off.

## Important limitations

- This alpha implementation buffers whole files in memory during package creation and restore; large profiles/PST files may exceed RAM.
- It does not preserve ACLs, owners, EFS semantics, alternate data streams, all timestamps, Windows registry settings, or every application profile.
- Windows junctions/reparse points, OneDrive/cloud placeholders, locked files, long paths, and races between preview and restore need Windows-specific hardening.
- No durable resume journal or full rollback is implemented.
- Outlook discovery is not a complete Outlook migration. OST files are normally cache files and must not be treated as the only mailbox copy.
- Credential support is a checklist only. Use approved vendor workflows; never dump browser passwords, Windows Credential Manager secrets, password hashes or authentication tokens.
- Do not use on live customer data until the release gates in [BUILD_WINDOWS.md](../BUILD_WINDOWS.md) have passed.
